using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class JarRsParJarmHappyPathTests
{
    private static HttpClient CreateServerClient(bool noRedirects = true) => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: noRedirects);

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
        var items = doc.RootElement.GetProperty("items");
        Assert.IsTrue(items.GetArrayLength() > 0, "No realms available for test");
        return items[0].GetProperty("id").GetString()!;
    }

    private static (string verifier, string challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var verifier = Base64Url(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Base64Url(hash);
        return (verifier, challenge);
    }

    private static (string privatePem, string publicPem) CreateRsaKeyPair()
    {
        using var rsa = RSA.Create(2048);
        var priv = rsa.ExportPkcs8PrivateKeyPem();
        var pub = rsa.ExportSubjectPublicKeyInfoPem();
        return (priv, pub);
    }

    private static string BuildRs256Jar(string clientId, string redirectUri, string scope, string privatePem, string? audience = null)
    {
        var (verifier, challenge) = CreatePkcePair();
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privatePem.AsSpan());
        var key = new RsaSecurityKey(rsa.ExportParameters(true));
        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["iss"] = clientId,
            ["aud"] = audience ?? "mrwho",
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
            Audience = audience ?? "mrwho",
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime.AddMinutes(5),
            SigningCredentials = creds,
            Claims = claims
        };
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(desc);
    }

    [TestMethod]
    public async Task Par_Jar_Rs256_Jarm_Happy_Path_Works()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        authed.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        // Generate RSA key pair
        var (privPem, pubPem) = CreateRsaKeyPair();

        string clientId = $"rsjar_{Guid.NewGuid():N}";
        var redirectUri = "https://localhost:7555/callback";

        var createPayload = new
        {
            clientId,
            name = "RS256 PAR+JAR+JARM Test Client",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 2,   // Required
            jarMode = 2,   // Required
            jarmMode = 2,  // Required
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "RS256",
            jarRsaPublicKeyPem = pubPem,
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var respCreate = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(createPayload), Encoding.UTF8, "application/json"));
        var bodyCreate = await respCreate.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, respCreate.StatusCode, $"Client creation failed: {bodyCreate}");

        // Build RS256 JAR
        var scope = "openid";
        var jar = BuildRs256Jar(clientId, redirectUri, scope, privPem);

        // PAR push
        using var parClient = CreateServerClient();
        var parForm = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["request"] = jar
        };
        var parResp = await parClient.PostAsync("connect/par", new FormUrlEncodedContent(parForm));
        var parBody = await parResp.Content.ReadAsStringAsync();
        Assert.IsTrue(parResp.IsSuccessStatusCode, $"PAR failed: {(int)parResp.StatusCode} {parBody}");
        using var parDoc = JsonDocument.Parse(parBody);
        var requestUri = parDoc.RootElement.GetProperty("request_uri").GetString();
        Assert.IsNotNull(requestUri, "PAR response missing request_uri");

        // Authorization (JARM enforced -> response JWT expected in 'response' param or redirect chain)
        using var authClient = CreateServerClient();
        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request_uri={Uri.EscapeDataString(requestUri!)}&response_mode=jwt";
        var authResp = await authClient.GetAsync(authorizeUrl);

        // Accept redirect to login (3xx) or initial OK with rendered login page
        bool success = (int)authResp.StatusCode is >= 300 and <= 399 || authResp.StatusCode == HttpStatusCode.OK;
        if (!success)
        {
            var failBody = await authResp.Content.ReadAsStringAsync();
            Assert.Fail($"Authorize expected redirect/OK, got {(int)authResp.StatusCode} {authResp.StatusCode}. Body: {failBody}");
        }
    }
}
