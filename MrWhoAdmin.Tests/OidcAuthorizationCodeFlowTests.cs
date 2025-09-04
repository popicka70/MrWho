using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Tests full authorization code + PKCE flow and refresh, userinfo, revocation.
/// These rely on the seeded mrwho_admin_web client and admin user.
/// </summary>
[TestClass]
[TestCategory("OIDC")] 
public class OidcAuthorizationCodeFlowTests
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var verifierBytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64Url(verifierBytes);
        using var sha = SHA256.Create();
        var challenge = Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private async Task<(string Code, string Verifier)> PerformAuthorizationAsync()
    {
        // Need redirect handling disabled so we can capture 302 Location header containing code
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

        var (verifier, challenge) = CreatePkcePair();
        var redirectUri = "https://localhost:7257/signin-oidc"; // seeded redirect
        var scope = "openid profile email offline_access mrwho.use";

        var authorizeUrl = $"connect/authorize?response_type=code&client_id=mrwho_admin_web&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&scope={HttpUtility.UrlEncode(scope)}&code_challenge={challenge}&code_challenge_method=S256";

        // 1. GET login page (will redirect to login since no cookie)
        var loginPage = await http.GetAsync(authorizeUrl);
        loginPage.StatusCode.Should().Be(HttpStatusCode.Redirect);
        loginPage.Headers.Location!.ToString().Should().Contain("/connect/login");

        // 2. Follow to get antiforgery cookie + form (simplify by not parsing token: testing pipeline uses ValidateAntiForgeryToken so we must extract)
        var loginGet = await http.GetAsync(loginPage.Headers.Location);
        loginGet.StatusCode.Should().Be(HttpStatusCode.OK);
        var html = await loginGet.Content.ReadAsStringAsync();
        // Extract __RequestVerificationToken if present
        string? token = null;
        var marker = "name=\"__RequestVerificationToken\" value=\"";
        var idx = html.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx > -1)
        {
            var start = idx + marker.Length;
            var end = html.IndexOf('"', start);
            if (end > start) token = html.Substring(start, end - start);
        }

        // 3. POST credentials (admin seeded user)
        var form = new Dictionary<string, string>
        {
            ["Email"] = "admin@mrwho.local",
            ["Password"] = "Adm1n#2025!G7x",
            ["RememberMe"] = "false"
        };
        if (token != null) form.Add("__RequestVerificationToken", token);
        var loginPost = await http.PostAsync("/connect/login", new FormUrlEncodedContent(form));
        loginPost.StatusCode.Should().Be(HttpStatusCode.Redirect);
        // Should redirect back to authorize endpoint (with original params or an intermediate)

        // 4. Follow redirect to authorization again with authenticated cookie
        var afterLogin = await http.GetAsync(loginPost.Headers.Location);
        afterLogin.StatusCode.Should().Be(HttpStatusCode.Redirect);

        var location = afterLogin.Headers.Location!.ToString();
        location.Should().StartWith(redirectUri);
        location.Should().Contain("code=");

        var uri = new Uri(location);
        var query = HttpUtility.ParseQueryString(uri.Query);
        var code = query["code"]!;
        code.Should().NotBeNullOrEmpty();
        return (code, verifier);
    }

    private async Task<JsonDocument> RedeemCodeAsync(string code, string verifier)
    {
        using var tokenClient = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var redirectUri = "https://localhost:7257/signin-oidc";
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "MrWhoAdmin2024!SecretKey",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier
        };
        var resp = await tokenClient.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var json = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue("token exchange should succeed: {0} - {1}", resp.StatusCode, json);
        return JsonDocument.Parse(json);
    }

    private static JsonWebToken ParseJwt(string jwt)
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(jwt);
        token.Should().NotBeNull();
        return token;
    }

    [TestMethod]
    public async Task AuthorizationCodeFlow_With_PKCE_Returns_Tokens()
    {
        var (code, verifier) = await PerformAuthorizationAsync();
        using var doc = await RedeemCodeAsync(code, verifier);

        doc.RootElement.TryGetProperty("access_token", out var at).Should().BeTrue();
        doc.RootElement.TryGetProperty("id_token", out var id).Should().BeTrue();
        doc.RootElement.TryGetProperty("refresh_token", out var rt).Should().BeTrue();

        var accessToken = ParseJwt(at.GetString()!);
        accessToken.Claims.Should().Contain(c => c.Type == "scp" && c.Value.Contains("mrwho.use"));
        var idToken = ParseJwt(id.GetString()!);
        idToken.Claims.Should().Contain(c => c.Type == "sub");
    }

    [TestMethod]
    public async Task Can_Use_Refresh_Token()
    {
        var (code, verifier) = await PerformAuthorizationAsync();
        using var doc = await RedeemCodeAsync(code, verifier);
        var refresh = doc.RootElement.GetProperty("refresh_token").GetString();

        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "MrWhoAdmin2024!SecretKey",
            ["refresh_token"] = refresh!
        };
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var json = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue("refresh should succeed: {0} {1}", resp.StatusCode, json);
        using var refreshed = JsonDocument.Parse(json);
        refreshed.RootElement.TryGetProperty("access_token", out _).Should().BeTrue();
    }

    [TestMethod]
    public async Task UserInfo_Returns_Profile_Claims()
    {
        var (code, verifier) = await PerformAuthorizationAsync();
        using var doc = await RedeemCodeAsync(code, verifier);
        var at = doc.RootElement.GetProperty("access_token").GetString();

        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", at);
        var resp = await client.GetAsync("connect/userinfo");
        var json = await resp.Content.ReadAsStringAsync();
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "userinfo should succeed: {0} {1}", resp.StatusCode, json);
        json.Should().Contain("sub");
    }

    [TestMethod]
    public async Task Revocation_Invalidates_Refresh_Token()
    {
        var (code, verifier) = await PerformAuthorizationAsync();
        using var doc = await RedeemCodeAsync(code, verifier);
        var refresh = doc.RootElement.GetProperty("refresh_token").GetString();

        // Revoke
        using (var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true))
        {
            var form = new Dictionary<string, string>
            {
                ["token"] = refresh!,
                ["token_type_hint"] = "refresh_token",
                ["client_id"] = "mrwho_admin_web",
                ["client_secret"] = "MrWhoAdmin2024!SecretKey"
            };
            var revoke = await client.PostAsync("connect/revocation", new FormUrlEncodedContent(form));
            revoke.IsSuccessStatusCode.Should().BeTrue();
        }

        // Attempt refresh again
        using (var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true))
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = "mrwho_admin_web",
                ["client_secret"] = "MrWhoAdmin2024!SecretKey",
                ["refresh_token"] = refresh!
            };
            var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
            resp.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);
            var body = await resp.Content.ReadAsStringAsync();
            body.Should().ContainAny("invalid_grant", "invalid_token");
        }
    }
}
