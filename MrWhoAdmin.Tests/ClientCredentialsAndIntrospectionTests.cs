using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography; // added
using System.Text; // added
using System.Web; // added
using System.Text.RegularExpressions; // added

namespace MrWhoAdmin.Tests;

/// <summary>
/// Tests client_credentials grant and token introspection/userinfo restrictions.
/// </summary>
[TestClass]
[TestCategory("OIDC")] 
public class ClientCredentialsAndIntrospectionTests
{
    private async Task<JsonDocument> RequestClientCredentialsAsync(string clientId = "mrwho_m2m", string secret = "MrWhoM2MSecret2025!")
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = "mrwho.use api.read"
        };
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var json = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue("client credentials should succeed: {0} {1}", resp.StatusCode, json);
        return JsonDocument.Parse(json);
    }

    // --- Helpers for performing authorization code + PKCE flow for demo1 user/client ---
    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=') .Replace('+', '-') .Replace('/', '_');

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var verifierBytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64Url(verifierBytes);
        using var sha = SHA256.Create();
        var challenge = Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static string? ExtractAntiforgeryToken(string html)
    {
        const string marker = "name=\"__RequestVerificationToken\" value=\"";
        var idx = html.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx > -1)
        {
            var start = idx + marker.Length; var end = html.IndexOf('"', start); if (end > start) return html.Substring(start, end - start);
        }
        var m = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"(?<val>[^\"]+)\"", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups["val"].Value : null;
    }

    private static string? ExtractHiddenReturnUrl(string html)
    {
        var m = Regex.Match(html, "name=\"returnUrl\"[^>]*value=\"(?<val>[^\"]+)\"", RegexOptions.IgnoreCase);
        return m.Success ? System.Net.WebUtility.HtmlDecode(m.Groups["val"].Value) : null;
    }

    private async Task<string> GetDemo1UserAccessTokenAsync()
    {
        const string clientId = "mrwho_demo1";
        const string clientSecret = "Demo1Secret2024!";
        const string redirectUri = "https://localhost:7037/signin-oidc"; // seeded redirect
        const string userEmail = "demo1@example.com";
        const string userPassword = "Dem0!User#2025";
        var scopes = "openid profile email api.read api.write";

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var (verifier, challenge) = CreatePkcePair();
        var authorizeUrlBase = $"connect/authorize?response_type=code&client_id={clientId}&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&scope={HttpUtility.UrlEncode(scopes)}&code_challenge={challenge}&code_challenge_method=S256";

        string? loginRedirectUrl = null; // capture original login redirect with encoded returnUrl/clientId

        async Task<string?> TryAuthorizeAsync()
        {
            var r = await http.GetAsync(authorizeUrlBase);
            if (r.StatusCode == HttpStatusCode.Redirect)
            {
                var loc = r.Headers.Location!.ToString();
                if (loc.StartsWith(redirectUri) && loc.Contains("code="))
                {
                    var uri = new Uri(loc); var q = HttpUtility.ParseQueryString(uri.Query); return q["code"]; }
                if (loc.Contains("/connect/login")) { loginRedirectUrl = loc; return null; }
            }
            else if (r.StatusCode == HttpStatusCode.OK)
            {
                var body = await r.Content.ReadAsStringAsync();
                if (body.Contains("<form") && body.Contains("Password")) return null;
            }
            return null;
        }

        var initialCode = await TryAuthorizeAsync();
        if (initialCode != null)
        {
            return await RedeemAsync(initialCode, verifier, clientId, clientSecret, redirectUri);
        }

        // Fetch login page (prefer captured redirect URL so hidden fields contain proper returnUrl/clientId)
        var loginPageUrl = loginRedirectUrl ?? "/connect/login";
        var loginPage = await http.GetAsync(loginPageUrl);
        loginPage.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginHtml = await loginPage.Content.ReadAsStringAsync();
        var antiForgery = ExtractAntiforgeryToken(loginHtml);
        var hiddenReturnUrl = ExtractHiddenReturnUrl(loginHtml); // capture existing hidden returnUrl if provided

        async Task<HttpResponseMessage> PostLoginAsync(string? token)
        {
            // Build absolute authorize URL from current base address if hidden not present
            var authorizeAbsolute = new Uri(http.BaseAddress!, authorizeUrlBase).ToString();
            var returnUrlToUse = hiddenReturnUrl ?? authorizeAbsolute;
            var loginForm = new Dictionary<string, string>
            {
                ["Email"] = userEmail,
                ["Password"] = userPassword,
                ["RememberMe"] = "false",
                ["returnUrl"] = returnUrlToUse,
                ["clientId"] = clientId
            };
            if (!string.IsNullOrEmpty(token)) loginForm.Add("__RequestVerificationToken", token);
            return await http.PostAsync("/connect/login", new FormUrlEncodedContent(loginForm));
        }

        var loginPost = await PostLoginAsync(antiForgery);
        if (loginPost.StatusCode == HttpStatusCode.BadRequest)
        {
            var retry = await http.GetAsync(loginPageUrl);
            var retryHtml = await retry.Content.ReadAsStringAsync();
            antiForgery = ExtractAntiforgeryToken(retryHtml);
            hiddenReturnUrl = ExtractHiddenReturnUrl(retryHtml) ?? hiddenReturnUrl;
            loginPost = await PostLoginAsync(antiForgery);
        }

        loginPost.StatusCode.Should().BeOneOf(new[]{HttpStatusCode.Redirect, HttpStatusCode.OK}, "login should either redirect or present view");

        var afterLoginCode = await TryAuthorizeAsync();
        if (afterLoginCode == null)
        {
            // fallback with new PKCE
            (verifier, challenge) = CreatePkcePair();
            var fallbackAuthorize = $"connect/authorize?response_type=code&client_id={clientId}&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&scope={HttpUtility.UrlEncode(scopes)}&code_challenge={challenge}&code_challenge_method=S256";
            var r = await http.GetAsync(fallbackAuthorize);
            if (r.StatusCode == HttpStatusCode.Redirect)
            {
                var loc = r.Headers.Location!.ToString();
                if (loc.StartsWith(redirectUri) && loc.Contains("code="))
                {
                    var uri = new Uri(loc); var q = HttpUtility.ParseQueryString(uri.Query); afterLoginCode = q["code"]; }
            }
        }

        afterLoginCode.Should().NotBeNull("after login we should receive an authorization code");
        return await RedeemAsync(afterLoginCode!, verifier, clientId, clientSecret, redirectUri);
    }

    private static async Task<string> RedeemAsync(string code, string verifier, string clientId, string clientSecret, string redirectUri)
    {
        using var tokenClient = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var tokenForm = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier
        };
        var tokenResp = await tokenClient.PostAsync("connect/token", new FormUrlEncodedContent(tokenForm));
        var tokenJson = await tokenResp.Content.ReadAsStringAsync();
        tokenResp.IsSuccessStatusCode.Should().BeTrue("token exchange should succeed: {0} {1}", tokenResp.StatusCode, tokenJson);
        using var doc = JsonDocument.Parse(tokenJson);
        var at = doc.RootElement.GetProperty("access_token").GetString();
        at.Should().NotBeNullOrWhiteSpace();
        return at!;
    }

    [TestMethod]
    public async Task ClientCredentials_Returns_AccessToken_No_Refresh()
    {
        using var doc = await RequestClientCredentialsAsync();
        doc.RootElement.TryGetProperty("access_token", out var at).Should().BeTrue();
        doc.RootElement.TryGetProperty("refresh_token", out _).Should().BeFalse();
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(at.GetString()!);
        jwt.Claims.Should().Contain(c => c.Type == "scope" && c.Value.Contains("api.read"));
    }

    [TestMethod]
    public async Task UserInfo_Fails_For_ClientCredentials_Token()
    {
        using var doc = await RequestClientCredentialsAsync();
        var access = doc.RootElement.GetProperty("access_token").GetString();
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var resp = await http.GetAsync("connect/userinfo");
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK, "client credentials token should not access userinfo");
    }

    [TestMethod]
    public async Task Introspection_With_Authorized_Client_Returns_Active()
    {
        var userAccessToken = await GetDemo1UserAccessTokenAsync();

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var req = new HttpRequestMessage(HttpMethod.Post, "connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["token"] = userAccessToken
            })
        };
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("mrwho_m2m:MrWhoM2MSecret2025!"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        var resp = await http.SendAsync(req);
        var payload = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue("introspection should succeed: {0} {1}", resp.StatusCode, payload);
        payload.Should().Contain("\"active\":true");

        using var doc = JsonDocument.Parse(payload);
        var root = doc.RootElement;
        root.TryGetProperty("active", out var activeProp).Should().BeTrue();
        activeProp.GetBoolean().Should().BeTrue();
        root.TryGetProperty("token_type", out var typeProp).Should().BeTrue("token_type expected");
        typeProp.GetString().Should().NotBeNullOrWhiteSpace();
        root.TryGetProperty("client_id", out var clientIdProp).Should().BeTrue();
        clientIdProp.GetString().Should().Be("mrwho_demo1");
        if (root.TryGetProperty("scope", out var scopeProp))
        {
            var scopeString = scopeProp.GetString();
            scopeString.Should().NotBeNull();
            var scopes = scopeString!.Split(new[]{' '}, StringSplitOptions.RemoveEmptyEntries).Distinct().OrderBy(s => s).ToArray();
            scopes.Should().Contain("api.read");
            scopes.Should().Contain("openid");
            scopes.Length.Should().Be(scopes.Distinct().Count());
        }
        else Assert.Fail("Introspection response did not include 'scope' property");
    }

    [TestMethod]
    public async Task Introspection_Fails_For_Client_Without_Permission()
    {
        using var sourceTokenDoc = await RequestClientCredentialsAsync();
        var token = sourceTokenDoc.RootElement.GetProperty("access_token").GetString();

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var req = new HttpRequestMessage(HttpMethod.Post, "connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["token"] = token!
            })
        };
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("mrwho_demo1:Demo1Secret2024!"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        var resp = await http.SendAsync(req);
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);
    }

    [TestMethod]
    public async Task M2M_Client_Runtime_Introspection_Flag_Exposed()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await client.GetAsync("debug/client-flags?client_id=mrwho_m2m");
        resp.IsSuccessStatusCode.Should().BeTrue("debug/client-flags should return 200 for mrwho_m2m");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        bool TryBool(string name, out bool value)
        {
            value = false; if (!doc.RootElement.TryGetProperty(name, out var prop)) return false; value = prop.GetBoolean(); return true;
        }

        TryBool("allowAccessToIntrospectionEndpoint", out var introspectFlag).Should().BeTrue();
        introspectFlag.Should().BeTrue("mrwho_m2m should have introspection enabled at runtime");
        TryBool("allowAccessToUserInfoEndpoint", out var userInfoFlag).Should().BeTrue();
        userInfoFlag.Should().BeFalse("mrwho_m2m should NOT have userinfo access");
        TryBool("allowAccessToRevocationEndpoint", out var revocationFlag).Should().BeTrue();
        revocationFlag.Should().BeTrue("mrwho_m2m should have revocation access");
        TryBool("allowClientCredentialsFlow", out var cc).Should().BeTrue();
        cc.Should().BeTrue("mrwho_m2m must allow client credentials");
        TryBool("allowAuthorizationCodeFlow", out var ac).Should().BeTrue();
        ac.Should().BeFalse("mrwho_m2m should not allow authorization code flow");
        TryBool("allowPasswordFlow", out var pwd).Should().BeTrue();
        pwd.Should().BeFalse("mrwho_m2m should not allow password flow");
        TryBool("allowRefreshTokenFlow", out var refresh).Should().BeTrue();
        refresh.Should().BeFalse("mrwho_m2m should not allow refresh tokens");
    }

    [TestMethod]
    public async Task OpenIddict_Runtime_Permissions_Contain_Introspection_For_M2M()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await client.GetAsync("debug/openiddict-application?client_id=mrwho_m2m");
        resp.IsSuccessStatusCode.Should().BeTrue("runtime OpenIddict application fetch should succeed");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement; root.TryGetProperty("permissions", out var perms).Should().BeTrue();
        perms.ValueKind.Should().Be(JsonValueKind.Array);
        var list = perms.EnumerateArray().Select(e => e.GetString()!).ToList();
        list.Should().Contain("endpoints.introspection", "OpenIddict app must include introspection permission");
        list.Should().Contain(e => e == "endpoints.token" || e == "ept:token", "token endpoint permission missing (endpoints.token/ept:token)");
        list.Should().Contain(e => e == "grant_types.client_credentials" || e == "gt:client_credentials", "client_credentials grant permission missing");
        list.Should().Contain(e => e == "endpoints.revocation" || e == "ept:revocation", "revocation endpoint permission missing");
    }
}
