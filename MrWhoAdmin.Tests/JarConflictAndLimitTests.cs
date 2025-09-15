using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")] // Covers PJ40 (parameter conflicts) + PJ41 (limits)
public class JarConflictAndLimitTests
{
    private const string DemoClientId = "mrwho_demo1"; // seeded confidential client with HS256 capability
    private const string DemoClientSecret = "PyfrZln6d2ifAbdL_2gr316CERUMyzfpgmxJ1J3xJsWUnfHGakcvjWenB_OwQqnv"; // long secret (>=32)
    private const string RedirectUri = "https://localhost:7037/signin-oidc";

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');

    private static SigningCredentials Hs256Creds()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(DemoClientSecret));
        return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    private static string CreateJar(Dictionary<string, object> claims)
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var desc = new SecurityTokenDescriptor
        {
            Issuer = DemoClientId,
            Audience = "mrwho", // logical audience accepted by server handler (normalized internally)
            NotBefore = now.UtcDateTime.AddMinutes(-1),
            Expires = now.UtcDateTime.AddMinutes(5),
            Claims = claims,
            SigningCredentials = Hs256Creds()
        };
        return handler.CreateToken(desc);
    }

    private static async Task<JsonDocument> GetDiscoveryAsync(HttpClient http)
    {
        using var resp = await http.GetAsync(".well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }

    private static async Task<HttpResponseMessage> AuthorizeAsync(HttpClient http, string jar, string extraQuery)
    {
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(DemoClientId)}&request={Uri.EscapeDataString(jar)}{extraQuery}";
        return await http.GetAsync(url);
    }

    [TestMethod]
    public async Task PJ40_Scope_Conflict_Detected()
    {
        // Request object carries scope=openid email profile; query purposely uses different (adds roles) -> conflict expected
        var jarClaims = new Dictionary<string, object>
        {
            ["client_id"] = DemoClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = RedirectUri,
            ["scope"] = "openid email profile",
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = "conflictchallenge",
            ["code_challenge_method"] = "S256",
            ["jti"] = Guid.NewGuid().ToString("n")
        };
        var jar = CreateJar(jarClaims);

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await AuthorizeAsync(http, jar, "&scope=openid%20email%20profile%20roles");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 for scope conflict. Status={(int)resp.StatusCode} Body={body}");
        StringAssert.Contains(body, "parameter_conflict:scope", "Scope conflict indicator missing");
    }

    [TestMethod]
    public async Task PJ41_MaxParameters_Limit_Enforced()
    {
        // MaxParameters set to 5 (via env). We'll send >5 distinct names after merge to trigger limit.
        var jarClaims = new Dictionary<string, object>
        {
            ["client_id"] = DemoClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = RedirectUri,
            ["scope"] = "openid profile",
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = "limitchallenge",
            ["code_challenge_method"] = "S256",
            ["extra1"] = "v1",
            ["extra2"] = "v2",
            ["extra3"] = "v3",
            ["jti"] = Guid.NewGuid().ToString("n")
        };
        var jar = CreateJar(jarClaims);

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await AuthorizeAsync(http, jar, string.Empty);
        var body = await resp.Content.ReadAsStringAsync();
        // Depending on evaluation order, handler should reject with limit_exceeded:parameters (or possibly name/value length if config changes). Accept either 400 + limit_exceeded token.
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 for parameter limit. Status={(int)resp.StatusCode} Body={body}");
        StringAssert.Contains(body, "limit_exceeded:parameters", "Parameter limit indicator missing");
    }

    [TestMethod]
    public async Task PJ41_MaxAggregateBytes_Limit_Enforced()
    {
        // Build a large claim value set to exceed aggregate 1024 bytes (configured). Each chunk ~130 bytes -> 9 chunks > 1024
        var bigValue = new string('a', 130);
        var jarClaims = new Dictionary<string, object>
        {
            ["client_id"] = DemoClientId,
            ["response_type"] = "code",
            ["redirect_uri"] = RedirectUri,
            ["scope"] = "openid profile",
            ["state"] = Guid.NewGuid().ToString("n"),
            ["nonce"] = Guid.NewGuid().ToString("n"),
            ["code_challenge"] = "byteschallenge",
            ["code_challenge_method"] = "S256",
            ["chunk1"] = bigValue,
            ["chunk2"] = bigValue,
            ["chunk3"] = bigValue,
            ["chunk4"] = bigValue,
            ["chunk5"] = bigValue,
            ["chunk6"] = bigValue,
            ["chunk7"] = bigValue,
            ["chunk8"] = bigValue,
            ["chunk9"] = bigValue,
            ["jti"] = Guid.NewGuid().ToString("n")
        };
        var jar = CreateJar(jarClaims);
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await AuthorizeAsync(http, jar, string.Empty);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 for aggregate bytes limit. Status={(int)resp.StatusCode} Body={body}");
        StringAssert.Contains(body, "limit_exceeded:aggregate_bytes", "Aggregate bytes limit indicator missing");
    }
}
