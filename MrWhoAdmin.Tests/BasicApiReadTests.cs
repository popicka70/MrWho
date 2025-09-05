using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Basic read-only API tests using a client_credentials access token (mrwho_m2m) with mrwho.use + api.read scopes.
/// Uses dynamic base address from Aspire test host instead of hard-coded port.
/// </summary>
[TestClass]
[TestCategory("Integration")] 
public class BasicApiReadTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private async Task<string?> GetAccessTokenAsync()
    {
        // Dynamic base address (may be http or https depending on Aspire assignment)
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "mrwho_m2m",
            ["client_secret"] = "MrWhoM2MSecret2025!",
            ["scope"] = "mrwho.use api.read"
        };

        using var content = new FormUrlEncodedContent(form);
        var response = await client.PostAsync("connect/token", content); // relative path to dynamic base
        var json = await response.Content.ReadAsStringAsync();
        Assert.IsTrue(response.IsSuccessStatusCode, $"token request should succeed (status {response.StatusCode}) payload: {json}");
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("access_token", out var at) ? at.GetString() : null;
    }

    private async Task<HttpClient> CreateAuthorizedClientAsync()
    {
        var token = await GetAccessTokenAsync();
        Assert.IsFalse(string.IsNullOrEmpty(token), "access token should be present");

        var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<(string? FirstId, string RawJson)> GetFirstItemAsync(HttpClient client, string relativeListUrl)
    {
        var resp = await client.GetAsync(relativeListUrl);
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode, $"{relativeListUrl} should return 200");
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"), "paged result should contain items property");
        try
        {
            using var doc = JsonDocument.Parse(payload);
            if (doc.RootElement.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array && items.GetArrayLength() > 0)
            {
                var first = items[0];
                if (first.TryGetProperty("id", out var idProp) && idProp.GetString() is { Length: > 0 } idStr)
                {
                    return (idStr, payload);
                }
            }
        }
        catch { /* ignore parse errors; will return no id */ }
        return (null, payload);
    }

    [TestMethod]
    public async Task Can_Acquire_Token_With_M2M_Client()
    {
        var token = await GetAccessTokenAsync();
        Assert.IsFalse(string.IsNullOrEmpty(token));
    }

    [TestMethod]
    public async Task Realms_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/realms?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    [TestMethod]
    public async Task ApiResources_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/apiresources?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    [TestMethod]
    public async Task IdentityResources_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/identityresources?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    // === Additional list endpoints ===

    [TestMethod]
    public async Task Clients_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/clients?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    [TestMethod]
    public async Task Scopes_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/scopes?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    [TestMethod]
    public async Task Roles_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/roles?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    [TestMethod]
    public async Task Users_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/users?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("items"));
    }

    [TestMethod]
    public async Task ClaimTypes_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/claimtypes?page=1&pageSize=5");
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Contains("type"));
    }

    [TestMethod]
    public async Task ClientTypes_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/clienttypes"); // may not be paged
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode);
        var payload = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(payload.Length > 2, "expect non-empty JSON (e.g., array)");
    }

    // === Detail & export endpoints (conditional) ===

    [TestMethod]
    public async Task Can_Get_First_Realm_By_Id_And_Export()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/realms?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // no realms yet
        var detail = await client.GetAsync($"api/realms/{id}");
        Assert.AreEqual(HttpStatusCode.OK, detail.StatusCode);
        var export = await client.GetAsync($"api/realms/{id}/export");
        Assert.AreEqual(HttpStatusCode.OK, export.StatusCode);
        var expPayload = await export.Content.ReadAsStringAsync();
        Assert.IsTrue(expPayload.Contains("\"name\""));
    }

    [TestMethod]
    public async Task Can_Get_First_Client_By_Id_And_Export()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/clients?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // no clients yet
        var detail = await client.GetAsync($"api/clients/{id}");
        Assert.AreEqual(HttpStatusCode.OK, detail.StatusCode);
        var export = await client.GetAsync($"api/clients/{id}/export");
        Assert.AreEqual(HttpStatusCode.OK, export.StatusCode);
    }

    [TestMethod]
    public async Task Can_Get_First_ApiResource_By_Id()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/apiresources?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // none
        var detail = await client.GetAsync($"api/apiresources/{id}");
        Assert.AreEqual(HttpStatusCode.OK, detail.StatusCode);
    }

    [TestMethod]
    public async Task Can_Get_First_IdentityResource_By_Id()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/identityresources?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // none
        var detail = await client.GetAsync($"api/identityresources/{id}");
        Assert.AreEqual(HttpStatusCode.OK, detail.StatusCode);
    }
}
