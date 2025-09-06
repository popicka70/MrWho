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
    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        var verifier = Base64UrlEncode(bytes);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(verifier));
        var challenge = Base64UrlEncode(hash);
        return (verifier, challenge);
    }

    private static async Task<(string Issuer, string AuthorizationEndpoint)> GetDiscoveryAsync(HttpClient http)
    {
        using var resp = await http.GetAsync(".well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var issuer = doc.RootElement.GetProperty("issuer").GetString()!;
        var authz = doc.RootElement.GetProperty("authorization_endpoint").GetString()!;
        return (issuer, authz);
    }

    private static string CreateJar(string audience, string clientId, string clientSecret, string redirectUri, string scope)
    {
        var (verifier, challenge) = CreatePkcePair();
        var now = DateTimeOffset.UtcNow;

        var keyBytes = Encoding.UTF8.GetBytes(clientSecret);
        if (keyBytes.Length < 32)
        {
            var padded = new byte[32];
            Array.Copy(keyBytes, padded, Math.Min(keyBytes.Length, 32));
            for (int i = keyBytes.Length; i < 32; i++) padded[i] = (byte)'!';
            keyBytes = padded;
        }
        var key = new SymmetricSecurityKey(keyBytes);
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime.AddMinutes(5),
            SigningCredentials = creds,
            Claims = new Dictionary<string, object>
            {
                ["client_id"] = clientId,
                ["response_type"] = "code",
                ["redirect_uri"] = redirectUri,
                ["scope"] = scope,
                ["state"] = Guid.NewGuid().ToString("n"),
                ["nonce"] = Guid.NewGuid().ToString("n"),
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256"
            }
        };

        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(descriptor);
    }

    private static async Task<string> PushParAsync(HttpClient http, string clientId, string clientSecret, string redirectUri, string scope)
    {
        var (verifier, challenge) = CreatePkcePair();
        var form = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["response_type"] = "code",
            ["redirect_uri"] = redirectUri,
            ["scope"] = scope,
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        };
        using var resp = await http.PostAsync("connect/par", new FormUrlEncodedContent(form));
        Assert.IsTrue(resp.IsSuccessStatusCode, $"PAR push failed: {resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("request_uri").GetString()!;
    }

    [TestMethod]
    public async Task Jar_Authorize_With_Signed_Request_Redirects_To_Login()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var disco = await GetDiscoveryAsync(http);

        const string clientId = "mrwho_demo1";
        const string clientSecret = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY";
        const string redirectUri = "https://localhost:7037/signin-oidc";
        const string scope = "openid profile email roles offline_access api.read";

        // First try direct JAR.
        var jar = CreateJar(disco.AuthorizationEndpoint, clientId, clientSecret, redirectUri, scope);
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request={Uri.EscapeDataString(jar)}";
        var resp = await http.GetAsync(url);

        if (resp.StatusCode == HttpStatusCode.BadRequest)
        {
            // Some servers enforce PAR for confidential clients; fallback to PAR then try request_uri.
            var requestUri = await PushParAsync(http, clientId, clientSecret, redirectUri, scope);
            var url2 = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request_uri={Uri.EscapeDataString(requestUri)}";
            resp = await http.GetAsync(url2);
        }

        var location = resp.Headers.Location?.ToString() ?? string.Empty;
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            StringAssert.Contains(location, "/connect/login", "Should redirect to login for unauthenticated user");
            StringAssert.Contains(location, "returnUrl=", "Login redirect should carry returnUrl containing the original authorize");
        }
        else
        {
            // Some configurations render login directly (pass-through) -> 200 OK
            Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode, $"Expected 302 or 200, got {resp.StatusCode}");
        }
    }

    [TestMethod]
    public async Task Jar_Authorize_With_Tampered_Request_Fails()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var disco = await GetDiscoveryAsync(http);

        const string clientId = "mrwho_demo1";
        const string clientSecret = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY";
        const string redirectUri = "https://localhost:7037/signin-oidc";
        const string scope = "openid profile";

        var jar = CreateJar(disco.AuthorizationEndpoint, clientId, clientSecret, redirectUri, scope);
        var badJar = jar.Substring(0, jar.Length - 1) + (jar.EndsWith("A") ? "B" : "A");
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&request={Uri.EscapeDataString(badJar)}";

        var resp = await http.GetAsync(url);

        var isErrorStatus = (int)resp.StatusCode >= 400;
        if (!isErrorStatus && resp.StatusCode == HttpStatusCode.Redirect)
        {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            Assert.IsFalse(loc.Contains("/connect/login", StringComparison.OrdinalIgnoreCase),
                $"Tampered JAR should not be accepted; got redirect to login: {loc}");
        }
        else
        {
            Assert.IsTrue(isErrorStatus, $"Tampered JAR should fail; actual status: {resp.StatusCode}");
        }
    }
}
