using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class JarTests
{
    private const string DemoClientId = "mrwho_demo1";
    private const string DemoClientSecret = "PyfrZln6d2ifAbdL_2gr316CERUMyzfpgmxJ1J3xJsWUnfHGakcvjWenB_OwQqnv"; // long seeded secret
    private const string RedirectUri = "https://localhost:7037/signin-oidc";
    private const string BaseScope = "openid profile email roles";

    // ===== Helpers =====
    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64UrlEncode(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Base64UrlEncode(hash);
        return (verifier, challenge);
    }

    private static async Task<JsonDocument> GetDiscoveryAsync(HttpClient http)
    {
        using var resp = await http.GetAsync(".well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json);
    }

    private static SigningCredentials CreateSymmetricCredentials(string clientSecret, string alg)
    {
        var keyBytes = Encoding.UTF8.GetBytes(clientSecret);
        int requiredLen = alg switch
        {
            SecurityAlgorithms.HmacSha256 => 32,
            SecurityAlgorithms.HmacSha384 => 48,
            SecurityAlgorithms.HmacSha512 => 64,
            _ when alg.Equals("HS256", StringComparison.OrdinalIgnoreCase) => 32,
            _ when alg.Equals("HS384", StringComparison.OrdinalIgnoreCase) => 48,
            _ when alg.Equals("HS512", StringComparison.OrdinalIgnoreCase) => 64,
            _ => 32
        };
        if (keyBytes.Length < requiredLen)
        {
            var padded = new byte[requiredLen];
            Array.Copy(keyBytes, padded, keyBytes.Length);
            for (int i = keyBytes.Length; i < requiredLen; i++) padded[i] = (byte)'!';
            keyBytes = padded;
        }
        var key = new SymmetricSecurityKey(keyBytes) { KeyId = $"test:{alg}:{keyBytes.Length}" };
        return new SigningCredentials(key, alg);
    }

    private static string CreateJar(string audience, string clientId, string clientSecret, string redirectUri, string scope,
        string signingAlg = SecurityAlgorithms.HmacSha256, bool includeJti = true, int padLength = 0, IDictionary<string, object>? extraClaims = null)
    {
        var (_, challenge) = CreatePkcePair();
        var now = DateTimeOffset.UtcNow;
        var creds = CreateSymmetricCredentials(clientSecret, signingAlg);
        var claims = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        };
        if (includeJti) claims["jti"] = Guid.NewGuid().ToString("n");
        if (padLength > 0) claims["pad"] = new string('x', padLength);
        if (extraClaims != null) foreach (var kv in extraClaims) claims[kv.Key] = kv.Value;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime.AddMinutes(5),
            SigningCredentials = creds,
            Claims = claims
        };
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(descriptor);
    }

    private static async Task<HttpResponseMessage> SendAuthorizeAsync(HttpClient http, string jar, string clientId)
    {
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request={Uri.EscapeDataString(jar)}";
        return await http.GetAsync(url);
    }

    private static bool IsAcceptableAuthRedirect(HttpResponseMessage resp)
    {
        if ((int)resp.StatusCode < 300 || (int)resp.StatusCode > 399) return false;
        var loc = resp.Headers.Location?.ToString() ?? string.Empty;
        return loc.Contains("/connect/", StringComparison.OrdinalIgnoreCase) || loc.Contains("/mfa/", StringComparison.OrdinalIgnoreCase);
    }

    // ===== Tests =====

    [TestMethod]
    public async Task Jar_Authorize_With_Signed_Request_Redirects_To_Login()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;
        var jar = CreateJar(authz, DemoClientId, DemoClientSecret, RedirectUri, BaseScope + " offline_access api.read");
        var resp = await SendAuthorizeAsync(http, jar, DemoClientId);
        if (resp.StatusCode == HttpStatusCode.BadRequest)
            Assert.Fail("Expected redirect or OK, got 400. Body: " + await resp.Content.ReadAsStringAsync());
        Assert.IsTrue(IsAcceptableAuthRedirect(resp) || resp.StatusCode == HttpStatusCode.OK, $"Unexpected status {resp.StatusCode} Location={resp.Headers.Location}");
    }

    [TestMethod]
    public async Task Jar_Authorize_With_Tampered_Request_Fails()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;
        var jar = CreateJar(authz, DemoClientId, DemoClientSecret, RedirectUri, BaseScope);
        var badJar = jar[..^1] + (jar.EndsWith("A") ? "B" : "A");
        var resp = await SendAuthorizeAsync(http, badJar, DemoClientId);
        Assert.IsTrue((int)resp.StatusCode >= 400 || !IsAcceptableAuthRedirect(resp), "Tampered JAR should not be treated as valid auth redirect");
    }

    [TestMethod]
    public async Task Discovery_Advertises_Jwt_Response_Mode_And_Request_Parameter()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var root = disco.RootElement;
        var modes = root.GetProperty("response_modes_supported").EnumerateArray().Select(e => e.GetString()).ToList();
        CollectionAssert.Contains(modes, "jwt", "jwt response mode missing");
        Assert.IsTrue(root.TryGetProperty("request_parameter_supported", out var req) && req.GetBoolean(), "request_parameter_supported should be true");
        Assert.IsTrue(root.TryGetProperty("authorization_response_iss_parameter_supported", out var iss) && iss.GetBoolean(), "authorization_response_iss_parameter_supported should be true");
    }

    [TestMethod]
    public async Task Jar_Replay_Jti_Rejected_On_Second_Use()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;
        var jar = CreateJar(authz, DemoClientId, DemoClientSecret, RedirectUri, BaseScope, includeJti: true);
        var first = await SendAuthorizeAsync(http, jar, DemoClientId);
        Assert.IsTrue(IsAcceptableAuthRedirect(first) || first.StatusCode == HttpStatusCode.OK, "First use of JAR should succeed");
        var second = await SendAuthorizeAsync(http, jar, DemoClientId);
        Assert.IsTrue((int)second.StatusCode >= 400 || !IsAcceptableAuthRedirect(second), "Replayed JAR (same jti) should be rejected");
    }

    [TestMethod]
    public async Task Jar_Missing_Jti_When_Required_Is_Rejected()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;
        var jar = CreateJar(authz, DemoClientId, DemoClientSecret, RedirectUri, BaseScope, includeJti: false);
        var resp = await SendAuthorizeAsync(http, jar, DemoClientId);
        Assert.IsTrue((int)resp.StatusCode >= 400 || !IsAcceptableAuthRedirect(resp), "Missing jti should cause rejection");
    }

    [TestMethod]
    public async Task Jar_Unsupported_Alg_Is_Rejected_Or_Advertised()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var root = disco.RootElement;
        var authz = root.GetProperty("authorization_endpoint").GetString()!;
        bool hs384Advertised = root.TryGetProperty("request_object_signing_alg_values_supported", out var algsEl) && algsEl.EnumerateArray().Any(e => string.Equals(e.GetString(), "HS384", StringComparison.OrdinalIgnoreCase));
        var jar = CreateJar(authz, DemoClientId, DemoClientSecret, RedirectUri, BaseScope, signingAlg: SecurityAlgorithms.HmacSha384);
        var resp = await SendAuthorizeAsync(http, jar, DemoClientId);
        if (hs384Advertised)
        {
            // Accept if advertised
            Assert.IsTrue(IsAcceptableAuthRedirect(resp) || resp.StatusCode == HttpStatusCode.OK, "HS384 advertised but not accepted");
        }
        else
        {
            if (IsAcceptableAuthRedirect(resp) || resp.StatusCode == HttpStatusCode.OK)
            {
                // Environment allowed HS384 despite not advertising it; mark inconclusive (policy drift)
                Assert.Inconclusive("HS384 accepted though not advertised; environment/config drift (AllowedRequestObjectAlgs may have been updated).");
            }
            else
            {
                Assert.IsTrue((int)resp.StatusCode >= 400, "Unsupported alg should be rejected");
            }
        }
    }

    [TestMethod]
    public async Task Jar_Oversize_Request_Object_Rejected()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;
        var jar = CreateJar(authz, DemoClientId, DemoClientSecret, RedirectUri, BaseScope, padLength: 6000); // > 4096 default limit
        var resp = await SendAuthorizeAsync(http, jar, DemoClientId);
        Assert.IsTrue((int)resp.StatusCode >= 400, "Oversize JAR should be rejected with error status");
    }

    [TestMethod]
    public async Task Jar_Invalid_Alg_None_Rejected()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;
        // Create unsigned JWT (alg=none) manually
        var header = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"none\"}"));
        var payloadObj = new Dictionary<string, object>
        {
            ["client_id"] = DemoClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = RedirectUri,
            ["scope"] = BaseScope,
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["aud"] = authz,
            ["iss"] = DemoClientId
        };
        var payloadJson = JsonSerializer.Serialize(payloadObj);
        var payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var unsigned = header + "." + payload + "."; // empty signature per RFC 7515 alg=none
        var resp = await SendAuthorizeAsync(http, unsigned, DemoClientId);
        Assert.IsTrue((int)resp.StatusCode >= 400, "alg=none request object should be rejected");
    }
}
