using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Tests client_credentials grant and token introspection/userinfo restrictions.
/// </summary>
[TestClass]
[TestCategory("OIDC")] 
public class ClientCredentialsAndIntrospectionTests
{
    private async Task<JsonDocument> RequestClientCredentialsAsync(string clientId = "mrwho_m2m", string secret = "MrWhoM2MSecret2025!")
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = "mrwho.use api.read"
        };
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var json = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue("client credentials should succeed: {0} {1}", resp.StatusCode, json);
        return JsonDocument.Parse(json);
    }

    [TestMethod]
    public async Task ClientCredentials_Returns_AccessToken_No_Refresh()
    {
        using var doc = await RequestClientCredentialsAsync();
        doc.RootElement.TryGetProperty("access_token", out var at).Should().BeTrue();
        doc.RootElement.TryGetProperty("refresh_token", out _).Should().BeFalse();
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(at.GetString()!);
        jwt.Claims.Should().Contain(c => c.Type == "scope" && c.Value.Contains("api.read"));
    }

    [TestMethod]
    public async Task UserInfo_Fails_For_ClientCredentials_Token()
    {
        using var doc = await RequestClientCredentialsAsync();
        var access = doc.RootElement.GetProperty("access_token").GetString();
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var resp = await http.GetAsync("connect/userinfo");
        resp.StatusCode.Should().NotBe(HttpStatusCode.OK, "client credentials token should not access userinfo");
    }

    [TestMethod]
    public async Task Introspection_With_Authorized_Client_Returns_Active()
    {
        // Get a token from admin auth code flow first (reuse existing test helper pattern quickly via password grant if enabled else skip) - fallback to client_credentials token introspection
        using var sourceTokenDoc = await RequestClientCredentialsAsync();
        var token = sourceTokenDoc.RootElement.GetProperty("access_token").GetString();

        using var introspectClient = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        // Use mrwho_m2m which has introspection permission
        var form = new Dictionary<string,string>
        {
            ["token"] = token!,
            ["client_id"] = "mrwho_m2m",
            ["client_secret"] = "MrWhoM2MSecret2025!"
        };
        var resp = await introspectClient.PostAsync("connect/introspect", new FormUrlEncodedContent(form));
        var json = await resp.Content.ReadAsStringAsync();
        resp.IsSuccessStatusCode.Should().BeTrue("introspection should succeed: {0} {1}", resp.StatusCode, json);
        json.Should().Contain("\"active\":true");
    }

    [TestMethod]
    public async Task Introspection_Fails_For_Client_Without_Permission()
    {
        using var sourceTokenDoc = await RequestClientCredentialsAsync();
        var token = sourceTokenDoc.RootElement.GetProperty("access_token").GetString();

        using var introspectClient = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        // Use demo1 (does not allow client credentials + introspect); we expect failure
        var form = new Dictionary<string,string>
        {
            ["token"] = token!,
            ["client_id"] = "mrwho_demo1",
            ["client_secret"] = "Demo1Secret2024!" // present but introspection permission missing
        };
        var resp = await introspectClient.PostAsync("connect/introspect", new FormUrlEncodedContent(form));
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);
    }
}
