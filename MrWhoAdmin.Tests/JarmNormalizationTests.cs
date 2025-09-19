using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class JarmNormalizationTests
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

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var verifier = B64(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = B64(hash);
        return (verifier, challenge);
    }

    private static string? GetQueryParameter(string fullUrlOrPath, string key, Uri baseAddress)
    {
        if (!Uri.TryCreate(fullUrlOrPath, UriKind.Absolute, out var absolute))
            absolute = new Uri(baseAddress, fullUrlOrPath.StartsWith('/') ? fullUrlOrPath : "/" + fullUrlOrPath);
        var idx = absolute.ToString().IndexOf('?');
        if (idx < 0) return null;
        var query = absolute.ToString().Substring(idx);
        var parsed = QueryHelpers.ParseQuery(query);
        return parsed.TryGetValue(key, out var values) ? values.ToString() : null;
    }

    [TestMethod]
    public async Task Explicit_ResponseMode_Jwt_Is_Normalized_And_Flag_Injected()
    {
        var token = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        authed.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientId = $"jarmnorm_{Guid.NewGuid():N}";
        var redirectUri = "https://localhost:7721/cb";
        var (_, challenge) = CreatePkcePair();

        var payload = new
        {
            clientId,
            name = "JARM Normalization Client",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0,
            jarMode = 0,
            jarmMode = 1, // Optional, but explicit jwt requested
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var createResp = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, createResp.StatusCode, await createResp.Content.ReadAsStringAsync());

        // Provide response_mode=jwt explicitly
        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=openid&response_mode=jwt&code_challenge={challenge}&code_challenge_method=S256";
        using var authClient = CreateServerClient();
        var resp = await authClient.GetAsync(authorizeUrl);
        Assert.IsTrue(((int)resp.StatusCode >= 300 && (int)resp.StatusCode <= 399) || resp.StatusCode == HttpStatusCode.OK,
            $"Expected redirect/OK for explicit jwt response_mode. Status={(int)resp.StatusCode} Body={await resp.Content.ReadAsStringAsync()}");

        if ((int)resp.StatusCode is >= 300 and <= 399)
        {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            var returnUrlRaw = GetQueryParameter(loc, "returnUrl", authClient.BaseAddress!);
            if (!string.IsNullOrEmpty(returnUrlRaw))
            {
                var decoded = Uri.UnescapeDataString(returnUrlRaw);
                Assert.IsTrue(decoded.Contains("mrwho_jarm=1", StringComparison.Ordinal), "mrwho_jarm flag missing in normalized returnUrl");
                Assert.IsFalse(decoded.Contains("response_mode=jwt", StringComparison.OrdinalIgnoreCase), "response_mode parameter should have been normalized away");
            }
            else
            {
                Assert.IsTrue(loc.Contains("mrwho_jarm=1", StringComparison.Ordinal), "mrwho_jarm flag missing in redirect location");
                Assert.IsFalse(loc.Contains("response_mode=jwt", StringComparison.OrdinalIgnoreCase), "response_mode should not remain in redirect URL after normalization");
            }
        }
    }

    [TestMethod]
    public async Task Required_JARM_With_Explicit_Jwt_ResponseMode_Normalizes_And_Flag_Injection()
    {
        var token = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        authed.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientId = $"jarmreq_{Guid.NewGuid():N}";
        var redirectUri = "https://localhost:7722/cb";
        var (_, challenge) = CreatePkcePair();

        var payload = new
        {
            clientId,
            name = "JARM Required Explicit Client",
            realmId,
            clientType = 1,
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            parMode = 0,
            jarMode = 0,
            jarmMode = 2, // Required
            redirectUris = new[] { redirectUri },
            scopes = new[] { "openid" }
        };
        var createResp = await authed.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.Created, createResp.StatusCode, await createResp.Content.ReadAsStringAsync());

        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=openid&response_mode=jwt&code_challenge={challenge}&code_challenge_method=S256";
        using var authClient = CreateServerClient();
        var resp = await authClient.GetAsync(authorizeUrl);
        Assert.IsTrue(((int)resp.StatusCode >= 300 && (int)resp.StatusCode <= 399) || resp.StatusCode == HttpStatusCode.OK,
            $"Expected redirect/OK. Status={(int)resp.StatusCode} Body={await resp.Content.ReadAsStringAsync()}");

        if ((int)resp.StatusCode is >= 300 and <= 399)
        {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            var returnUrlRaw = GetQueryParameter(loc, "returnUrl", authClient.BaseAddress!);
            if (!string.IsNullOrEmpty(returnUrlRaw))
            {
                var decoded = Uri.UnescapeDataString(returnUrlRaw);
                Assert.IsTrue(decoded.Contains("mrwho_jarm=1", StringComparison.Ordinal), "mrwho_jarm flag missing in returnUrl");
                Assert.IsFalse(decoded.Contains("response_mode=jwt", StringComparison.OrdinalIgnoreCase), "response_mode should have been normalized away");
            }
            else
            {
                Assert.IsTrue(loc.Contains("mrwho_jarm=1", StringComparison.Ordinal), "mrwho_jarm flag missing in redirect location");
                Assert.IsFalse(loc.Contains("response_mode=jwt", StringComparison.OrdinalIgnoreCase), "response_mode should have been normalized away");
            }
        }
    }
}
