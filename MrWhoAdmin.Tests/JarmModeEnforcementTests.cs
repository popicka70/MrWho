using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")] 
public class JarmModeEnforcementTests
{
    private static HttpClient CreateServerClient(bool noRedirects = true) => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: noRedirects);

    private static async Task<string> GetAdminAccessTokenAsync()
    {
        using var http = CreateServerClient();
        var form = new Dictionary<string,string>
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

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
        var verifier = B64(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = B64(hash);
        return (verifier, challenge);
    }

    // Task 17: JarmMode=Required without providing response_mode=jwt should be silently enforced (middleware injects mrwho_jarm)
    [TestMethod]
    public async Task JarmMode_Required_Without_ResponseMode_Query_Is_Enforced()
    {
        var token = await GetAdminAccessTokenAsync();
        using var authed = CreateServerClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        authed.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var realmId = await GetFirstRealmIdAsync(authed);

        var clientId = RandomClientId("jarmforce");
        var redirectUri = "https://localhost:7710/cb";
        var (verifier, challenge) = CreatePkcePair();

        var payload = new
        {
            clientId,
            name = "JARM Required Enforcement Client",
            realmId,
            clientType = 1, // Public
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
        var createBody = await createResp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, createResp.StatusCode, $"Client creation failed: {createBody}");

        // Intentionally omit response_mode=jwt
        var authorizeUrl = $"connect/authorize?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=openid&code_challenge={challenge}&code_challenge_method=S256";
        using var authClient = CreateServerClient();
        var authResp = await authClient.GetAsync(authorizeUrl);

        // Expect redirect (login) or OK (rendered login) but NOT a 400
        Assert.IsTrue(((int)authResp.StatusCode >=300 && (int)authResp.StatusCode <=399) || authResp.StatusCode == HttpStatusCode.OK,
            $"Expected redirect/OK. Got {(int)authResp.StatusCode} {authResp.StatusCode}. Body: {await authResp.Content.ReadAsStringAsync()}" );

        // If redirect, confirm middleware injected mrwho_jarm flag (evidence of enforcement)
        if ((int)authResp.StatusCode is >=300 and <=399)
        {
            var loc = authResp.Headers.Location?.ToString() ?? string.Empty;
            StringAssert.Contains(loc, "mrwho_jarm=1", "mrwho_jarm flag not present in redirect location when JarmMode=Required");
        }
    }
}
