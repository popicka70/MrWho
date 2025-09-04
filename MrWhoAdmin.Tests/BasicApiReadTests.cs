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
        response.IsSuccessStatusCode.Should().BeTrue(
            "token request should succeed (status {0}) payload: {1}", response.StatusCode, json);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("access_token", out var at) ? at.GetString() : null;
    }

    private async Task<HttpClient> CreateAuthorizedClientAsync()
    {
        var token = await GetAccessTokenAsync();
        token.Should().NotBeNullOrEmpty("access token should be present");

        var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<(string? FirstId, string RawJson)> GetFirstItemAsync(HttpClient client, string relativeListUrl)
    {
        var resp = await client.GetAsync(relativeListUrl);
        resp.StatusCode.Should().Be(HttpStatusCode.OK, "{0} should return 200", relativeListUrl);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items", "paged result should contain items property");
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
        token.Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task Realms_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/realms?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items");
    }

    [TestMethod]
    public async Task ApiResources_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/apiresources?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items");
    }

    [TestMethod]
    public async Task IdentityResources_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/identityresources?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items");
    }

    // === Additional list endpoints ===

    [TestMethod]
    public async Task Clients_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/clients?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("items");
    }

    [TestMethod]
    public async Task Scopes_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/scopes?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("items");
    }

    [TestMethod]
    public async Task Roles_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/roles?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("items");
    }

    [TestMethod]
    public async Task Users_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/users?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("items");
    }

    [TestMethod]
    public async Task ClaimTypes_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/claimtypes?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        (await resp.Content.ReadAsStringAsync()).Should().Contain("type");
    }

    [TestMethod]
    public async Task ClientTypes_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("api/clienttypes"); // may not be paged
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Length.Should().BeGreaterThan(2); // expect non-empty JSON (e.g., array)
    }

    // === Detail & export endpoints (conditional) ===

    [TestMethod]
    public async Task Can_Get_First_Realm_By_Id_And_Export()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/realms?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // no realms yet
        var detail = await client.GetAsync($"api/realms/{id}");
        detail.StatusCode.Should().Be(HttpStatusCode.OK);
        var export = await client.GetAsync($"api/realms/{id}/export");
        export.StatusCode.Should().Be(HttpStatusCode.OK);
        (await export.Content.ReadAsStringAsync()).Should().Contain("\"name\"");
    }

    [TestMethod]
    public async Task Can_Get_First_Client_By_Id_And_Export()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/clients?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // no clients yet
        var detail = await client.GetAsync($"api/clients/{id}");
        detail.StatusCode.Should().Be(HttpStatusCode.OK);
        var export = await client.GetAsync($"api/clients/{id}/export");
        export.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [TestMethod]
    public async Task Can_Get_First_ApiResource_By_Id()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/apiresources?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // none
        var detail = await client.GetAsync($"api/apiresources/{id}");
        detail.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [TestMethod]
    public async Task Can_Get_First_IdentityResource_By_Id()
    {
        using var client = await CreateAuthorizedClientAsync();
        var (id, _) = await GetFirstItemAsync(client, "api/identityresources?page=1&pageSize=1");
        if (string.IsNullOrEmpty(id)) return; // none
        var detail = await client.GetAsync($"api/identityresources/{id}");
        detail.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
