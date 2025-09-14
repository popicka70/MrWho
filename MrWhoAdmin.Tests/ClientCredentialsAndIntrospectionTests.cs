using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class ClientCredentialsAndIntrospectionTests
{
    private async Task<JsonDocument> RequestClientCredentialsAsync(string clientId = "mrwho_m2m", string secret = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY")
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
        Assert.IsTrue(resp.IsSuccessStatusCode, $"client credentials should succeed: {resp.StatusCode} {json}");
        return JsonDocument.Parse(json);
    }

    [TestMethod]
    public async Task ClientCredentials_Returns_AccessToken_No_Refresh()
    {
        using var doc = await RequestClientCredentialsAsync();
        Assert.IsTrue(doc.RootElement.TryGetProperty("access_token", out var at));
        Assert.IsFalse(doc.RootElement.TryGetProperty("refresh_token", out _));
        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(at.GetString()!);
        Assert.IsTrue(jwt.Claims.Any(c => c.Type == "scope" && c.Value.Contains("api.read")));
    }

    [TestMethod]
    public async Task UserInfo_Fails_For_ClientCredentials_Token()
    {
        using var doc = await RequestClientCredentialsAsync();
        var access = doc.RootElement.GetProperty("access_token").GetString();
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var resp = await http.GetAsync("connect/userinfo");
        Assert.AreNotEqual(HttpStatusCode.OK, resp.StatusCode, "client credentials token should not access userinfo");
    }

    [TestMethod]
    public async Task Introspection_Fails_For_Client_Without_Permission()
    {
        using var sourceTokenDoc = await RequestClientCredentialsAsync();
        var token = sourceTokenDoc.RootElement.GetProperty("access_token").GetString();

        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var req = new HttpRequestMessage(HttpMethod.Post, "connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = token!
            })
        };
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("mrwho_demo1:FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY"));
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        var resp = await http.SendAsync(req);
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.BadRequest || resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden);
    }

    [TestMethod]
    public async Task M2M_Client_Runtime_Introspection_Flag_Exposed()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await client.GetAsync("debug/client-flags?client_id=mrwho_m2m");
        Assert.IsTrue(resp.IsSuccessStatusCode, "debug/client-flags should return 200 for mrwho_m2m");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        bool TryBool(string name, out bool value)
        {
            value = false; if (!doc.RootElement.TryGetProperty(name, out var prop)) return false; value = prop.GetBoolean(); return true;
        }

        Assert.IsTrue(TryBool("allowAccessToIntrospectionEndpoint", out var introspectFlag));
        Assert.IsTrue(introspectFlag, "mrwho_m2m should have introspection enabled at runtime");
        Assert.IsTrue(TryBool("allowAccessToUserInfoEndpoint", out var userInfoFlag));
        Assert.IsFalse(userInfoFlag, "mrwho_m2m should NOT have userinfo access");
        Assert.IsTrue(TryBool("allowAccessToRevocationEndpoint", out var revocationFlag));
        Assert.IsTrue(revocationFlag, "mrwho_m2m should have revocation access");
        Assert.IsTrue(TryBool("allowClientCredentialsFlow", out var cc));
        Assert.IsTrue(cc, "mrwho_m2m must allow client credentials");
        Assert.IsTrue(TryBool("allowAuthorizationCodeFlow", out var ac));
        Assert.IsFalse(ac, "mrwho_m2m should not allow authorization code flow");
        Assert.IsTrue(TryBool("allowPasswordFlow", out var pwd));
        Assert.IsFalse(pwd, "mrwho_m2m should not allow password flow");
        Assert.IsTrue(TryBool("allowRefreshTokenFlow", out var refresh));
        Assert.IsFalse(refresh, "mrwho_m2m should not allow refresh tokens");
    }

    [TestMethod]
    public async Task OpenIddict_Runtime_Permissions_Contain_Introspection_For_M2M()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await client.GetAsync("debug/openiddict-application?client_id=mrwho_m2m");
        Assert.IsTrue(resp.IsSuccessStatusCode, "runtime OpenIddict application fetch should succeed");
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.IsTrue(doc.RootElement.TryGetProperty("permissions", out var perms));
        Assert.AreEqual(JsonValueKind.Array, perms.ValueKind);
        var list = perms.EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.IsTrue(list.Contains("endpoints.introspection"), "Missing introspection permission");
        Assert.IsTrue(list.Any(e => e == "endpoints.token" || e == "ept:token"), "Missing token endpoint permission");
        Assert.IsTrue(list.Any(e => e == "grant_types.client_credentials" || e == "gt:client_credentials"), "Missing client_credentials grant permission");
        Assert.IsTrue(list.Any(e => e == "endpoints.revocation" || e == "ept:revocation"), "Missing revocation permission");
    }
}
