using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class JarmAssertionTests
{
    private static HttpClient CreateServerClient(bool disableRedirects = true, bool disableCookies = false)
        => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: disableRedirects, disableCookies: disableCookies);

    private static async Task<JsonDocument> GetDiscoveryAsync(HttpClient http)
    {
        using var resp = await http.GetAsync(".well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json);
    }

    private static async Task<string> GetAdminAccessTokenAsync(string scope = "openid profile email offline_access mrwho.use")
    {
        using var http = CreateServerClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = scope
        };
        var resp = await http.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(resp.IsSuccessStatusCode, $"Failed to obtain admin access token. Status {(int)resp.StatusCode}. Body: {body}");
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }

    private static async Task<string> GetFirstRealmIdAsync(HttpClient authed)
    {
        var resp = await authed.GetAsync("api/realms?page=1&pageSize=1");
        var json = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(resp.IsSuccessStatusCode, $"Failed to fetch realms. Status {(int)resp.StatusCode}. Body: {json}");
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("items")[0].GetProperty("id").GetString()!;
    }

    private static (string verifier, string challenge) CreatePkcePair()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=')[..].Replace('+', '-').Replace('/', '_');
        var verifier = B64(bytes);
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = B64(hash);
        return (verifier, challenge);
    }

    private static string ExtractAntiForgeryToken(string html)
    {
        // Look for input named __RequestVerificationToken
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : string.Empty;
    }

    private static string? GetQueryParam(string url, string key)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return null;
        var q = System.Web.HttpUtility.ParseQueryString(u.Query);
        return q[key];
    }

    private static DateTime GetIatUtc(JsonWebToken jwt)
    {
        var iatText = jwt.Claims.FirstOrDefault(c => c.Type == "iat")?.Value;
        if (long.TryParse(iatText, out var iatSec))
        {
            return DateTimeOffset.FromUnixTimeSeconds(iatSec).UtcDateTime;
        }
        return DateTime.MinValue;
    }

    private static DateTime GetExpUtc(JsonWebToken jwt)
    {
        var expText = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
        if (long.TryParse(expText, out var expSec))
        {
            return DateTimeOffset.FromUnixTimeSeconds(expSec).UtcDateTime;
        }
        return jwt.ValidTo; // fallback
    }

    private static string? GetClaimValue(JsonWebToken jwt, string type)
        => jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, type, StringComparison.Ordinal))?.Value;

    [TestMethod]
    public async Task JARM_Success_Response_JWT_Has_iss_aud_iat_exp_code_state()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient(disableRedirects: true, disableCookies: false);
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        authed.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        // Create a public client that allows auth code, PKCE and optional JARM (we'll request response_mode=jwt)
        var clientId = $"jarm_success_{Guid.NewGuid():N}";
        var redirectUri = "https://localhost:7555/cb"; // keep short to avoid login-short indirection
        var createPayload = new
        {
            clientId,
            name = "JARM Success Assertions",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0,
            jarMode = 0,
            jarmMode = 1, // Optional
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var respCreate = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(createPayload), Encoding.UTF8, "application/json"));
        var bodyCreate = await respCreate.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, respCreate.StatusCode, bodyCreate);

        // Build authorize URL
        var (_, challenge) = CreatePkcePair();
        var state = Guid.NewGuid().ToString("n");
        var authorizeUrl = $"/connect/authorize?client_id={Uri.EscapeDataString(clientId)}&response_type=code&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope=openid&state={state}&code_challenge={challenge}&code_challenge_method=S256&response_mode=jwt&mrwho_consent=ok";

        // Start login with returnUrl = authorizeUrl
        using var http = CreateServerClient(disableRedirects: true, disableCookies: false);
        var initialLoginUrl = $"/connect/login?returnUrl={Uri.EscapeDataString(http.BaseAddress + authorizeUrl.TrimStart('/'))}&clientId={Uri.EscapeDataString(clientId)}";
        var loginGet = await http.GetAsync(initialLoginUrl);
        // Follow one redirect if login-short used
        if ((int)loginGet.StatusCode is >= 300 and <= 399 && loginGet.Headers.Location != null)
        {
            var loc = loginGet.Headers.Location.ToString();
            loginGet = await http.GetAsync(loc.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? loc : (http.BaseAddress + loc.TrimStart('/')));
        }
        var loginHtml = await loginGet.Content.ReadAsStringAsync();
        Assert.IsTrue(loginHtml.Contains("__RequestVerificationToken"), "Login page should contain anti-forgery token");
        var token = ExtractAntiForgeryToken(loginHtml);
        Assert.IsFalse(string.IsNullOrEmpty(token), "Failed to extract anti-forgery token");

        // POST credentials
        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["Email"] = "admin@mrwho.local",
            ["Password"] = "Adm1n#2025!G7x",
            ["RememberMe"] = "false"
        };
        // Post back to the same login endpoint we fetched (supports login-short)
        var postTarget = loginGet.RequestMessage?.RequestUri?.ToString() ?? initialLoginUrl;
        if (!postTarget.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            postTarget = new Uri(http.BaseAddress!, postTarget).ToString();
        var post = await http.PostAsync(postTarget, new FormUrlEncodedContent(form));

        // Expect redirect to authorize first, then to redirect_uri with response param
        Assert.IsTrue((int)post.StatusCode is >= 300 and <= 399, $"Login POST should redirect. Status={(int)post.StatusCode}");
        var next = post.Headers.Location?.ToString() ?? string.Empty;
        // Follow to authorize (relative OK)
        if (!next.StartsWith("http", StringComparison.OrdinalIgnoreCase)) next = new Uri(http.BaseAddress!, next).ToString();
        var authResp = await http.GetAsync(next);
        Assert.IsTrue((int)authResp.StatusCode is >= 300 and <= 399, $"Authorize should redirect to redirect_uri. Status={(int)authResp.StatusCode} Body={await authResp.Content.ReadAsStringAsync()}");
        var finalLoc = authResp.Headers.Location?.ToString() ?? string.Empty;
        StringAssert.Contains(finalLoc, redirectUri, "Redirect should go to configured redirect_uri");
        var jarm = GetQueryParam(finalLoc, "response");
        Assert.IsFalse(string.IsNullOrEmpty(jarm), "Missing JARM 'response' parameter");

        // Decode JWT without validation and assert claims
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(jarm);
        using var disco = await GetDiscoveryAsync(CreateServerClient());
        var expectedIssuer = disco.RootElement.GetProperty("issuer").GetString()!.TrimEnd('/');
        var iss = jwt.Issuer?.TrimEnd('/') ?? string.Empty;
        Assert.AreEqual(expectedIssuer, iss, "iss mismatch");
        Assert.AreEqual(clientId, jwt.Audiences.FirstOrDefault(), "aud mismatch");
        var code = GetClaimValue(jwt, "code");
        Assert.IsFalse(string.IsNullOrEmpty(code), "code missing in JARM response");
        var stateClaim = GetClaimValue(jwt, "state");
        Assert.AreEqual(state, stateClaim, "state mismatch");
        var iatUtc = GetIatUtc(jwt);
        var expUtc = GetExpUtc(jwt);
        Assert.IsTrue(iatUtc > DateTime.MinValue, "iat missing");
        Assert.IsTrue(expUtc > DateTime.UtcNow, "exp should be in the future");
        var lifetime = expUtc - iatUtc;
        Assert.IsTrue(lifetime.TotalSeconds is > 30 and <= 300, $"Unexpected JARM token lifetime: {lifetime}");
    }

    [TestMethod]
    public async Task JARM_Error_Response_JWT_Has_iss_aud_iat_exp_error_state()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient(disableRedirects: true, disableCookies: false);
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        authed.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientId = $"jarm_error_{Guid.NewGuid():N}";
        var redirectUri = "https://localhost:7556/cb";
        var createPayload = new
        {
            clientId,
            name = "JARM Error Assertions",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0,
            jarMode = 0,
            jarmMode = 1,
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var respCreate = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(createPayload), Encoding.UTF8, "application/json"));
        var bodyCreate = await respCreate.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, respCreate.StatusCode, bodyCreate);

        var (_, challenge) = CreatePkcePair();
        var state = Guid.NewGuid().ToString("n");
        // prompt=none with no session should yield login_required error packaged as JARM JWT
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&response_type=code&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope=openid&state={state}&code_challenge={challenge}&code_challenge_method=S256&response_mode=jwt&prompt=none";
        using var http = CreateServerClient(disableRedirects: true, disableCookies: false);
        var resp = await http.GetAsync(url);
        Assert.IsTrue((int)resp.StatusCode is >= 300 and <= 399, $"Expected redirect to redirect_uri. Status={(int)resp.StatusCode} Body={await resp.Content.ReadAsStringAsync()}");
        var loc = resp.Headers.Location?.ToString() ?? string.Empty;
        StringAssert.Contains(loc, redirectUri, "Final redirect should target redirect_uri");
        var jarm = GetQueryParam(loc, "response");
        Assert.IsFalse(string.IsNullOrEmpty(jarm), "Missing JARM 'response' parameter");

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(jarm);
        using var disco = await GetDiscoveryAsync(CreateServerClient());
        var expectedIssuer = disco.RootElement.GetProperty("issuer").GetString()!.TrimEnd('/');
        Assert.AreEqual(expectedIssuer, (jwt.Issuer ?? string.Empty).TrimEnd('/'), "iss mismatch");
        Assert.AreEqual(clientId, jwt.Audiences.FirstOrDefault(), "aud mismatch");
        Assert.IsNull(GetClaimValue(jwt, "code"), "code should not be present in error JARM");
        var err = GetClaimValue(jwt, "error");
        Assert.AreEqual("login_required", err, "Unexpected error code in JARM");
        Assert.AreEqual(state, GetClaimValue(jwt, "state"), "state mismatch");
        var iatUtc = GetIatUtc(jwt); var expUtc = GetExpUtc(jwt);
        Assert.IsTrue(expUtc > DateTime.UtcNow, "exp should be in the future");
        Assert.IsTrue((expUtc - iatUtc).TotalSeconds is > 30 and <= 300, "Unexpected lifetime");
    }
}
