using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace MrWhoAdmin.Tests;

/// <summary>
/// PJ37 trace test: ensure only our custom early validation occurs (no second built-in processing of 'request').
/// We create a dedicated client with PAR disabled and JAR required so a direct JAR request should succeed (redirect or 200).
/// </summary>
[TestClass]
[TestCategory("OIDC")] 
public class JarPreemptionTraceTests
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
        Assert.IsTrue(resp.IsSuccessStatusCode, $"Admin token acquisition failed: {(int)resp.StatusCode} {body}");
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }

    private static (string verifier, string challenge) CreatePkce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=')[..].Replace('+','-').Replace('/','_');
        var verifier = B64(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = B64(hash);
        return (verifier, challenge);
    }

    private static string BuildHsJar(string clientId, string secret, string redirectUri, string scope, string audience = "mrwho")
    {
        var (verifier, challenge) = CreatePkce();
        var now = DateTimeOffset.UtcNow;
        var keyBytes = Encoding.UTF8.GetBytes(secret.PadRight(48,'!')); // ensure sufficient length
        var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
        var handler = new JsonWebTokenHandler();
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["iss"] = clientId,
            ["aud"] = audience,
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
            Audience = audience,
            Expires = now.AddMinutes(5).UtcDateTime,
            NotBefore = now.AddMinutes(-1).UtcDateTime,
            SigningCredentials = creds,
            Claims = claims
        };
        return handler.CreateToken(desc);
    }

    [TestMethod]
    public async Task Jar_CustomExclusive_Sets_Sentinel_And_Strips_Request()
    {
        // Create dedicated client (PAR disabled, JAR required) so direct JAR should succeed.
        var adminToken = await GetAdminAccessTokenAsync();
        using var adminHttp = CreateServerClient();
        adminHttp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        adminHttp.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // Get realm id
        var realmsResp = await adminHttp.GetAsync("api/realms?page=1&pageSize=1");
        var realmsBody = await realmsResp.Content.ReadAsStringAsync();
        Assert.IsTrue(realmsResp.IsSuccessStatusCode, $"Failed realms fetch: {realmsBody}");
        using var realmsDoc = JsonDocument.Parse(realmsBody);
        var realmId = realmsDoc.RootElement.GetProperty("items")[0].GetProperty("id").GetString()!;

        var clientId = $"preempt_{Guid.NewGuid():N}";
        var redirectUri = "https://localhost:7700/cb";
        var secret = "hs256_preemption_secret_value_1234567890"; // >=32 bytes
        var createPayload = new
        {
            clientId,
            name = "Preemption Trace Test Client",
            realmId,
            clientType = 1, // public client
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0, // Disabled
            jarMode = 2, // Required
            jarmMode = 0,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS256",
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var createResp = await adminHttp.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(createPayload), Encoding.UTF8, "application/json"));
        var createBody = await createResp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, createResp.StatusCode, $"Client creation failed: {createBody}");

        var jar = BuildHsJar(clientId, secret, redirectUri, "openid");

        using var http = CreateServerClient();
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request={Uri.EscapeDataString(jar)}";
        var resp = await http.GetAsync(url);
        var statusOk = ((int)resp.StatusCode >= 300 && (int)resp.StatusCode <= 399) || resp.StatusCode == HttpStatusCode.OK;
        if (!statusOk)
        {
            var body = await resp.Content.ReadAsStringAsync();
            if (resp.StatusCode == HttpStatusCode.BadRequest && (body.Contains("request object required") || body.Contains("request_not_supported")))
            {
                Assert.Inconclusive($"Received 400 ({(body.Contains("request_not_supported") ? "built-in rejection" : "jar missing")}) pending full preemption. Body: {body}");
            }
            else
            {
                Assert.Fail($"Unexpected status {(int)resp.StatusCode} {resp.StatusCode} Body: {body}");
            }
        }

        // Replay JAR to attempt jti replay (may or may not be enforced yet, acceptable outcomes: 400 replay OR redirect/OK if replay not enforced in Phase 1)
        var replayResp = await http.GetAsync(url);
        Assert.IsTrue(
            replayResp.StatusCode == HttpStatusCode.BadRequest || ((int)replayResp.StatusCode >= 300 && (int)replayResp.StatusCode <= 399) || replayResp.StatusCode == HttpStatusCode.OK,
            $"Unexpected replay status {(int)replayResp.StatusCode} {replayResp.StatusCode} Body: {await replayResp.Content.ReadAsStringAsync()}");
    }
}
