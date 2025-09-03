using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Basic read-only API tests using a client_credentials access token (mrwho_tests_m2m) with mrwho.use + api.read scopes.
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
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho");

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "mrwho_tests_m2m",
            ["client_secret"] = "TestM2MSecret2025!",
            // mrwho.use required by AdminClientApi policy; api.read for list endpoints
            ["scope"] = "mrwho.use api.read"
        };

        using var content = new FormUrlEncodedContent(form);
        var response = await client.PostAsync("/connect/token", content);
        response.IsSuccessStatusCode.Should().BeTrue("token request should succeed (status {0})", response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("access_token", out var at) ? at.GetString() : null;
    }

    private async Task<HttpClient> CreateAuthorizedClientAsync()
    {
        var token = await GetAccessTokenAsync();
        token.Should().NotBeNullOrEmpty("access token should be present");
        var client = SharedTestInfrastructure.CreateHttpClient("mrwho");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    [TestMethod]
    public async Task Can_Acquire_Token_With_Test_M2M_Client()
    {
        var token = await GetAccessTokenAsync();
        token.Should().NotBeNullOrEmpty();
    }

    [TestMethod]
    public async Task Realms_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("/api/realms?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items");
    }

    [TestMethod]
    public async Task ApiResources_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("/api/apiresources?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items");
    }

    [TestMethod]
    public async Task IdentityResources_List_Returns_Data()
    {
        using var client = await CreateAuthorizedClientAsync();
        var resp = await client.GetAsync("/api/identityresources?page=1&pageSize=5");
        resp.StatusCode.Should().Be(HttpStatusCode.OK);
        var payload = await resp.Content.ReadAsStringAsync();
        payload.Should().Contain("items");
    }
}
