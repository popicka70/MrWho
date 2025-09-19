using System.Net;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Tests native JarMode=Required enforcement (PJ37) ensuring old middleware removal does not regress behavior.
/// </summary>
[TestClass]
[TestCategory("OIDC")]
public class JarModeEnforcementTests
{
    private static HttpClient CreateServerClient(bool noRedirects = true) => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: noRedirects);

    private static async Task<string> GetAdminAccessTokenAsync()
    {
        using var http = CreateServerClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = "openid profile email offline_access mrwho.use"
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

    private static string RandomClientId(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private static (string verifier, string challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var verifier = B64(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = B64(hash);
        return (verifier, challenge);
    }

    private static string BuildHsJar(string clientId, string secret, string redirectUri, string scope)
    {
        var (verifier, challenge) = CreatePkcePair();
        var now = DateTimeOffset.UtcNow;
        // Ensure required length
        if (secret.Length < 48) secret = secret + new string('!', 48 - secret.Length);
        var creds = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)), SecurityAlgorithms.HmacSha256);
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["iss"] = clientId,
            ["aud"] = "mrwho",
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["jti"] = Guid.NewGuid().ToString("n")
        };
        var desc = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = "mrwho",
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime.AddMinutes(5),
            SigningCredentials = creds,
            Claims = claims
        };
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(desc);
    }

    [TestMethod]
    public async Task JarModeRequired_MissingRequestObject_Rejected()
    {
        var token = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient();
        authed.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        authed.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientId = RandomClientId("jarreq");
        var redirectUri = "https://localhost:7900/cb";
        var payload = new
        {
            clientId,
            name = "Jar Required Enforcement Client",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0,
            jarMode = 2, // Required
            jarmMode = 0,
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var createResp = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        var createBody = await createResp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, createResp.StatusCode, $"Client creation failed: {createBody}");

        using var http = CreateServerClient();
        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=openid";
        var resp = await http.GetAsync(authorizeUrl);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 for missing request object. Body={body}");
        StringAssert.Contains(body, "request object required", "Missing JAR error not surfaced by handler");
    }

    [TestMethod]
    public async Task JarModeRequired_WithValidJar_SucceedsInitialRedirect()
    {
        var token = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient();
        authed.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        authed.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientId = RandomClientId("jarok");
        var redirectUri = "https://localhost:7901/cb";
        var secret = "valid_hs256_secret_value_for_tests_1234567890";
        var payload = new
        {
            clientId,
            name = "Jar Required OK Client",
            realmId,
            clientType = 0, // Confidential to use secret if needed later
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = true,
            clientSecret = secret,
            parMode = 0,
            jarMode = 2,
            jarmMode = 0,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS256",
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var createResp = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, createResp.StatusCode, await createResp.Content.ReadAsStringAsync());

        var jar = BuildHsJar(clientId, secret, redirectUri, "openid");
        using var http = CreateServerClient();
        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request={Uri.EscapeDataString(jar)}";
        var resp = await http.GetAsync(authorizeUrl);
        // Accept redirect to login or inline OK (login page). Not 400.
        Assert.IsTrue(((int)resp.StatusCode >= 300 && (int)resp.StatusCode <= 399) || resp.StatusCode == HttpStatusCode.OK,
            $"Expected redirect/OK with JAR provided. Status={(int)resp.StatusCode} Body={await resp.Content.ReadAsStringAsync()}");
    }
}
