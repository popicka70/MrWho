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
public class JarParJarmAdditionalTests
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

    private static HttpClient CreateAuthedAdminClient(string token)
    {
        var http = CreateServerClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return http;
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

    private static string RandomClientId(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
        var verifier = B64(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = B64(hash);
        return (verifier, challenge);
    }

    private static SigningCredentials CreateHsCreds(string secret, string alg)
    {
        var required = alg.EndsWith("512") ? 64 : alg.EndsWith("384") ? 48 : 32;
        var bytes = Encoding.UTF8.GetBytes(secret);
        if (bytes.Length < required)
        {
            var pad = new byte[required];
            Array.Copy(bytes, pad, bytes.Length);
            for (int i = bytes.Length; i < required; i++) pad[i] = (byte)'!';
            bytes = pad;
        }
        return new SigningCredentials(new SymmetricSecurityKey(bytes), alg);
    }

    private static string BuildHsJar(string audience, string clientId, string secret, string redirectUri, string scope, string alg = SecurityAlgorithms.HmacSha256, bool includeJti = true)
    {
        var (verifier, challenge) = CreatePkcePair();
        var now = DateTimeOffset.UtcNow;
        var creds = CreateHsCreds(secret, alg);
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
            ["code_challenge_method"] = "S256"
        };
        if (includeJti) claims["jti"] = Guid.NewGuid().ToString("n");
        var desc = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime.AddMinutes(5),
            SigningCredentials = creds,
            Claims = claims
        };
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(desc);
    }

    // 13: HS256 PAR + JAR + JARM happy path
    [TestMethod]
    public async Task Par_Jar_Hs256_Jarm_Happy_Path_Works()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateAuthedAdminClient(adminToken);
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientSecret = "hs256_super_secret_value_for_tests_1234567890"; // >32 bytes
        var clientId = RandomClientId("hsjar");
        var redirectUri = "https://localhost:7600/cb";

        var createPayload = new
        {
            clientId,
            name = "HS256 PAR+JAR+JARM Test Client",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = true,
            clientSecret,
            parMode = 2,
            jarMode = 2,
            jarmMode = 2,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS256",
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var respCreate = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(createPayload), Encoding.UTF8, "application/json"));
        var bodyCreate = await respCreate.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, respCreate.StatusCode, bodyCreate);

        // Build HS JAR
        var jar = BuildHsJar("mrwho", clientId, clientSecret, redirectUri, "openid");

        // PAR push
        using var parClient = CreateServerClient();
        var parForm = new Dictionary<string,string>{{"client_id", clientId},{"request", jar}};
        var parResp = await parClient.PostAsync("connect/par", new FormUrlEncodedContent(parForm));
        var parBody = await parResp.Content.ReadAsStringAsync();
        Assert.IsTrue(parResp.IsSuccessStatusCode, $"PAR failed: {parResp.StatusCode} {parBody}");
        using var parDoc = JsonDocument.Parse(parBody);
        var requestUri = parDoc.RootElement.GetProperty("request_uri").GetString();

        // Authorize with response_mode=jwt (explicit)
        using var authClient = CreateServerClient();
        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request_uri={Uri.EscapeDataString(requestUri!)}&response_mode=jwt";
        var authResp = await authClient.GetAsync(authorizeUrl);
        bool ok = (int)authResp.StatusCode is >=300 and <=399 || authResp.StatusCode == HttpStatusCode.OK;
        if (!ok)
        {
            var failBody = await authResp.Content.ReadAsStringAsync();
            Assert.Fail($"Authorize expected redirect/OK, got {(int)authResp.StatusCode}. Body: {failBody}");
        }
    }

    // 15: ParMode=Required without PAR (direct authorize should fail even with JAR)
    [TestMethod]
    public async Task ParMode_Required_Without_Par_Fails()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateAuthedAdminClient(adminToken);
        var realmId = await GetFirstRealmIdAsync(authed);
        var clientSecret = "hs256_secret_for_par_required_1234567890";
        var clientId = RandomClientId("parreq");
        var redirectUri = "https://localhost:7601/cb";
        var payload = new
        {
            clientId,
            name = "PAR Required Client",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = true,
            clientSecret,
            parMode = 2, // Required
            jarMode = 1, // Optional so direct jar would otherwise be accepted
            jarmMode = 0,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS256",
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var create = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, create.StatusCode, await create.Content.ReadAsStringAsync());

        var jar = BuildHsJar("mrwho", clientId, clientSecret, redirectUri, "openid");
        using var direct = CreateServerClient();
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request={Uri.EscapeDataString(jar)}";
        var resp = await direct.GetAsync(url);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 when PAR required. Body: {body}");
        StringAssert.Contains(body, "PAR required", "Error body should indicate PAR requirement");
    }

    // 16: JarMode=Required missing JAR
    [TestMethod]
    public async Task JarMode_Required_Missing_Jar_Fails()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateAuthedAdminClient(adminToken);
        var realmId = await GetFirstRealmIdAsync(authed);
        var clientId = RandomClientId("jarreqmiss");
        var redirectUri = "https://localhost:7602/cb";
        var payload = new
        {
            clientId,
            name = "Jar Required Missing",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0,
            jarMode = 2, // Required
            jarmMode = 0,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS256",
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var create = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, create.StatusCode, await create.Content.ReadAsStringAsync());

        using var http = CreateServerClient();
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=openid";
        var resp = await http.GetAsync(url);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 when JAR required and missing. Body: {body}");
        StringAssert.Contains(body, "request object required", "Error body should indicate JAR requirement");
    }

    // 18: Replay same JAR (same jti) via PAR twice
    [TestMethod]
    public async Task Par_Jar_Replay_Jti_Fails_On_Second_Push()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateAuthedAdminClient(adminToken);
        var realmId = await GetFirstRealmIdAsync(authed);
        var clientSecret = "hs256_secret_replay_12345678901234567890";
        var clientId = RandomClientId("replay");
        var redirectUri = "https://localhost:7603/cb";

        var payload = new
        {
            clientId,
            name = "Replay Test Client",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = true,
            clientSecret,
            parMode = 2,
            jarMode = 2,
            jarmMode = 0,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS256",
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var create = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, create.StatusCode, await create.Content.ReadAsStringAsync());

        // Build JAR with manual fixed jti to force replay detection
        var (verifier, challenge) = CreatePkcePair();
        var now = DateTimeOffset.UtcNow;
        var creds = CreateHsCreds(clientSecret, SecurityAlgorithms.HmacSha256);
        var fixedJti = Guid.NewGuid().ToString("n");
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["iss"] = clientId,
            ["aud"] = "mrwho",
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,
            ["scope"] = "openid",
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["jti"] = fixedJti
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
        var jar = handler.CreateToken(desc);

        using var par1 = CreateServerClient();
        var form1 = new Dictionary<string,string>{{"client_id", clientId},{"request", jar}};
        var r1 = await par1.PostAsync("connect/par", new FormUrlEncodedContent(form1));
        Assert.IsTrue(r1.IsSuccessStatusCode, await r1.Content.ReadAsStringAsync());

        using var par2 = CreateServerClient();
        var r2 = await par2.PostAsync("connect/par", new FormUrlEncodedContent(form1));
        var body2 = await r2.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, r2.StatusCode, $"Expected replay rejection. Body: {body2}");
        StringAssert.Contains(body2, "replay", "Replay indicator expected in error description");
    }

    // 19: HS512 + short secret policy rejection
    [TestMethod]
    public async Task CreateClient_HS512_ShortSecret_Rejected()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateAuthedAdminClient(adminToken);
        var realmId = await GetFirstRealmIdAsync(authed);
        var clientId = RandomClientId("hs512short");
        var shortSecret = "too_short_secret"; // <64 bytes
        var payload = new
        {
            clientId,
            name = "HS512 Short Secret",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = true,
            clientSecret = shortSecret,
            jarMode = 1,
            parMode = 1,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "HS512",
            redirectUris = new[] { "https://localhost:7604/cb" },
            scopes = new[] { "openid" }
        };
        var resp = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected policy rejection for short secret. Body: {body}");
        StringAssert.Contains(body, "Secret length", "Policy message should mention secret length");
    }

    // 20: Invalid RSA public key rejected at PAR (signature validation)
    [TestMethod]
    public async Task Par_With_Invalid_Rsa_Public_Key_Fails()
    {
        var adminToken = await GetAdminAccessTokenAsync();
        using var authed = CreateAuthedAdminClient(adminToken);
        var realmId = await GetFirstRealmIdAsync(authed);
        var clientId = RandomClientId("badrs");
        var redirectUri = "https://localhost:7605/cb";

        var invalidPem = "-----BEGIN PUBLIC KEY-----\nMIIBBADINVALIDKEYDATA1234567890ABCDE\n-----END PUBLIC KEY-----";

        var payload = new
        {
            clientId,
            name = "Invalid RSA Key Client",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 2,
            jarMode = 2,
            jarmMode = 0,
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "RS256",
            jarRsaPublicKeyPem = invalidPem,
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var create = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, create.StatusCode, await create.Content.ReadAsStringAsync());

        // Build a valid RS256 JAR with a different random RSA key (will not match invalid key and also invalid key parse should fail)
        using var rsa = RSA.Create(2048);
        var priv = rsa.ExportPkcs8PrivateKeyPem();
        var (verifier, challenge) = CreatePkcePair();
        var now = DateTimeOffset.UtcNow;
        var creds = new SigningCredentials(new RsaSecurityKey(rsa.ExportParameters(true)), SecurityAlgorithms.RsaSha256);
        var claims = new Dictionary<string,object>
        {
            ["client_id"] = clientId,
            ["iss"] = clientId,
            ["aud"] = "mrwho",
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,
            ["scope"] = "openid",
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["jti"] = Guid.NewGuid().ToString("n")
        };
        var desc = new SecurityTokenDescriptor { Issuer = clientId, Audience = "mrwho", NotBefore = now.UtcDateTime.AddMinutes(-1), Expires = now.UtcDateTime.AddMinutes(5), SigningCredentials = creds, Claims = claims };
        var handler = new JsonWebTokenHandler();
        var jar = handler.CreateToken(desc);

        using var parClient = CreateServerClient();
        var form = new Dictionary<string,string>{{"client_id", clientId},{"request", jar}};
        var parResp = await parClient.PostAsync("connect/par", new FormUrlEncodedContent(form));
        var parBody = await parResp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, parResp.StatusCode, $"Expected invalid RSA key rejection. Body: {parBody}");
        StringAssert.Contains(parBody, "invalid", "Error should indicate invalid request/object");
    }
}
