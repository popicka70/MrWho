using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("Configuration")]
public class JarJarmConfigurationValidationTests
{
    private static HttpClient CreateServerClient() => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

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

    private static HttpClient CreateAuthedAdminClient(string token)
    {
        var http = CreateServerClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return http;
    }

    private static string RandomClientId(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    [TestMethod]
    public async Task JarMode_Required_With_RequireSigned_False_Is_Rejected()
    {
        var token = await GetAdminAccessTokenAsync();
        using var http = CreateAuthedAdminClient(token);
        var realmId = await GetFirstRealmIdAsync(http);

        var payload = new
        {
            clientId = RandomClientId("jarreq_invalid1"),
            name = "Jar Required Invalid",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            jarMode = 2, // Required
            requireSignedRequestObject = false, // invalid per guard
            redirectUris = new[] { "https://localhost:7449/callback" },
            scopes = new[] { "openid" }
        };
        var resp = await http.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 for invalid combination. Body: {body}");
        StringAssert.Contains(body, "JarMode=Required", "Response should mention JarMode guard");
    }

    [TestMethod]
    public async Task RequireSignedRequestObject_True_Without_Alg_List_Is_Rejected()
    {
        var token = await GetAdminAccessTokenAsync();
        using var http = CreateAuthedAdminClient(token);
        var realmId = await GetFirstRealmIdAsync(http);

        var payload = new
        {
            clientId = RandomClientId("jarreq_invalid2"),
            name = "Jar Signed Missing Algs",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            jarMode = 1, // Optional
            requireSignedRequestObject = true, // requires alg list
            // allowedRequestObjectAlgs intentionally omitted
            redirectUris = new[] { "https://localhost:7450/callback" },
            scopes = new[] { "openid" }
        };
        var resp = await http.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, resp.StatusCode, $"Expected 400 for missing alg list. Body: {body}");
        StringAssert.Contains(body, "AllowedRequestObjectAlgs", "Response should mention alg list requirement");
    }

    [TestMethod]
    public async Task Valid_Jar_Required_Config_Creates_Client()
    {
        var token = await GetAdminAccessTokenAsync();
        using var http = CreateAuthedAdminClient(token);
        var realmId = await GetFirstRealmIdAsync(http);

        var payload = new
        {
            clientId = RandomClientId("jarreq_valid"),
            name = "Jar Required Valid",
            realmId,
            clientType = 1, // Public
            allowAuthorizationCodeFlow = true,
            requirePkce = true,
            requireClientSecret = false,
            jarMode = 2, // Required
            requireSignedRequestObject = true,
            allowedRequestObjectAlgs = "RS256", // satisfies guard
            redirectUris = new[] { "https://localhost:7451/callback" },
            scopes = new[] { "openid" }
        };
        var resp = await http.PostAsync("api/clients", new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.Created, resp.StatusCode, $"Expected 201 created. Body: {body}");
        using var doc = JsonDocument.Parse(body);
        Assert.IsTrue(doc.RootElement.TryGetProperty("id", out _), "Response should include client id");
        Assert.AreEqual("RS256", doc.RootElement.GetProperty("allowedRequestObjectAlgs").GetString(), "Alg list not persisted correctly");
    }
}
