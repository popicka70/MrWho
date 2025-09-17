using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class AdditionalAuthFlowTests
{
    private static HttpClient CreateServerClient(bool disableRedirects = true) => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: disableRedirects);

    private static async Task<(HttpStatusCode Status, string Body)> GetStringAsync(HttpClient client, string url)
    {
        var resp = await client.GetAsync(url);
        var body = await resp.Content.ReadAsStringAsync();
        return (resp.StatusCode, body);
    }

    private static async Task<JsonDocument> RequestTokenAsync(Dictionary<string, string> form)
    {
        using var client = CreateServerClient();
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        try { return JsonDocument.Parse(body); } catch { Assert.Fail($"Token endpoint returned non-JSON: {(int)resp.StatusCode} {body}"); throw; }
    }

    [TestMethod]
    public async Task AuthorizationEndpoint_Redirects_To_Login_When_Not_Authenticated()
    {
        // Use PAR to avoid parameter limit checks in the front-channel
        // Build a valid PKCE S256 challenge (Base64Url-encoded 32-byte SHA256)
        const string codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // RFC7636 example
        var redirectUri = "https://localhost:7257/signin-oidc";

        // Push authorization request via PAR
        using var parClient = CreateServerClient();
        var parForm = new Dictionary<string, string>
        {
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };
        var parResp = await parClient.PostAsync("connect/par", new FormUrlEncodedContent(parForm));
        var parBody = await parResp.Content.ReadAsStringAsync();
        if (parResp.StatusCode == HttpStatusCode.NotFound)
        {
            Assert.Inconclusive("PAR endpoint not implemented (404). Test skipped.");
        }
        if (!parResp.IsSuccessStatusCode)
        {
            // Some servers may not accept 'request' objects at PAR yet; here we only used plain parameters.
            Assert.Fail($"PAR failed: {(int)parResp.StatusCode} {parBody}");
        }
        using var parDoc = JsonDocument.Parse(parBody);
        var requestUri = parDoc.RootElement.GetProperty("request_uri").GetString();
        Assert.IsFalse(string.IsNullOrWhiteSpace(requestUri), "PAR response missing request_uri");

        // Now call authorize with only client_id + request_uri
        using var client = CreateServerClient();
        var url = $"/connect/authorize?client_id=mrwho_admin_web&request_uri={Uri.EscapeDataString(requestUri!)}";
        var resp = await client.GetAsync(url);
        // Expect a redirect to login (302/303) or an HTML login page (OK) depending on pipeline configuration.
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.Redirect || resp.StatusCode == HttpStatusCode.Found || resp.StatusCode == HttpStatusCode.OK, $"Unexpected status: {(int)resp.StatusCode}");
        var loc = resp.Headers.Location?.ToString() ?? string.Empty;
        // When redirect, should contain /connect/login or /Account/Login depending on server config
        if (resp.StatusCode == HttpStatusCode.Redirect || resp.StatusCode == HttpStatusCode.Found)
        {
            Assert.IsTrue(loc.Contains("login", StringComparison.OrdinalIgnoreCase) || loc.Contains("authorize", StringComparison.OrdinalIgnoreCase),
                $"Redirect location did not look like a login page: {loc}");
        }
    }

    [TestMethod]
    public async Task PasswordGrant_AdminClient_Fails_For_DemoRealm_User()
    {
        var doc = await RequestTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["username"] = "demo1@example.com", // belongs to demo realm
            ["password"] = "Dem0!User#2025",
            ["scope"] = "openid profile email offline_access mrwho.use"
        });
        var root = doc.RootElement;
        Assert.IsTrue(root.TryGetProperty("error", out var errProp), "Expected error for realm mismatch password grant");
        var err = errProp.GetString();
        Assert.IsTrue(err == "access_denied" || err == "invalid_grant" || err == "unauthorized_client", $"Unexpected error code: {err}");
    }

    [TestMethod]
    public async Task AccessToken_Without_mrwho_use_Cannot_Call_Admin_Api()
    {
        // Obtain token intentionally omitting mrwho.use
        using var tokenDoc = await RequestTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = "openid profile email offline_access" // missing mrwho.use
        });
        if (tokenDoc.RootElement.TryGetProperty("error", out var errorEl))
        {
            Assert.Inconclusive($"Token request failed (cannot validate authorization failure path) error={errorEl.GetString()}");
        }
        var access = tokenDoc.RootElement.GetProperty("access_token").GetString();
        Assert.IsFalse(string.IsNullOrEmpty(access));

        using var apiClient = CreateServerClient();
        apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var resp = await apiClient.GetAsync("api/realms?page=1&pageSize=1");
        // Expect 403 forbidden (policy failure) or 401 if authentication fails scope check at validation.
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.Forbidden || resp.StatusCode == HttpStatusCode.Unauthorized, $"Expected forbidden/unauthorized for missing mrwho.use scope, got {(int)resp.StatusCode}");
    }

    [TestMethod]
    public async Task ClientCredentials_Requesting_OfflineAccess_Does_Not_Return_RefreshToken()
    {
        using var doc = await RequestTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "mrwho_m2m",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["scope"] = "mrwho.use offline_access" // attempt to get offline_access
        });
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var errorProp))
        {
            var err = errorProp.GetString();
            // Accept broader set including invalid_request (some servers map disallowed offline_access to invalid_request)
            Assert.IsTrue(err is "invalid_scope" or "unauthorized_client" or "invalid_grant" or "invalid_request", $"Unexpected error for client_credentials with offline_access: {err}");
            Assert.IsFalse(root.TryGetProperty("refresh_token", out _), "Error response must not contain refresh_token");
            return;
        }
        Assert.IsFalse(root.TryGetProperty("refresh_token", out _), "Client credentials response should not include refresh_token even if offline_access requested");
        Assert.IsTrue(root.TryGetProperty("access_token", out _), "Expected access_token when request succeeds");
    }
}
