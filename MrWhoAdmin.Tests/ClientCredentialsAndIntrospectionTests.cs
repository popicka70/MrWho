using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Tests client_credentials grant and selected runtime flags. (Introspection success test dropped per request)
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
    public async Task Introspection_Fails_For_Client_Without_Permission()
    {
        using var sourceTokenDoc = await RequestClientCredentialsAsync();
        var token = sourceTokenDoc.RootElement.GetProperty("access_token").GetString();

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var req = new HttpRequestMessage(HttpMethod.Post, "connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["token"] = token!
            })
        };
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("mrwho_demo1:Demo1Secret2024!"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        var resp = await http.SendAsync(req);
        resp.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden);
    }

    [TestMethod]
    public async Task M2M_Client_Runtime_Introspection_Flag_Exposed()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await client.GetAsync("debug/client-flags?client_id=mrwho_m2m");
        resp.IsSuccessStatusCode.Should().BeTrue("debug/client-flags should return 200 for mrwho_m2m");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        bool TryBool(string name, out bool value)
        {
            value = false; if (!doc.RootElement.TryGetProperty(name, out var prop)) return false; value = prop.GetBoolean(); return true;
        }

        TryBool("allowAccessToIntrospectionEndpoint", out var introspectFlag).Should().BeTrue();
        introspectFlag.Should().BeTrue("mrwho_m2m should have introspection enabled at runtime");
        TryBool("allowAccessToUserInfoEndpoint", out var userInfoFlag).Should().BeTrue();
        userInfoFlag.Should().BeFalse("mrwho_m2m should NOT have userinfo access");
        TryBool("allowAccessToRevocationEndpoint", out var revocationFlag).Should().BeTrue();
        revocationFlag.Should().BeTrue("mrwho_m2m should have revocation access");
        TryBool("allowClientCredentialsFlow", out var cc).Should().BeTrue();
        cc.Should().BeTrue("mrwho_m2m must allow client credentials");
        TryBool("allowAuthorizationCodeFlow", out var ac).Should().BeTrue();
        ac.Should().BeFalse("mrwho_m2m should not allow authorization code flow");
        TryBool("allowPasswordFlow", out var pwd).Should().BeTrue();
        pwd.Should().BeFalse("mrwho_m2m should not allow password flow");
        TryBool("allowRefreshTokenFlow", out var refresh).Should().BeTrue();
        refresh.Should().BeFalse("mrwho_m2m should not allow refresh tokens");
    }

    [TestMethod]
    public async Task OpenIddict_Runtime_Permissions_Contain_Introspection_For_M2M()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await client.GetAsync("debug/openiddict-application?client_id=mrwho_m2m");
        resp.IsSuccessStatusCode.Should().BeTrue("runtime OpenIddict application fetch should succeed");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement; root.TryGetProperty("permissions", out var perms).Should().BeTrue();
        perms.ValueKind.Should().Be(JsonValueKind.Array);
        var list = perms.EnumerateArray().Select(e => e.GetString()!).ToList();
        list.Should().Contain("endpoints.introspection", "OpenIddict app must include introspection permission");
        list.Should().Contain(e => e == "endpoints.token" || e == "ept:token", "token endpoint permission missing (endpoints.token/ept:token)");
        list.Should().Contain(e => e == "grant_types.client_credentials" || e == "gt:client_credentials", "client_credentials grant permission missing");
        list.Should().Contain(e => e == "endpoints.revocation" || e == "ept:revocation", "revocation endpoint permission missing");
    }
}
