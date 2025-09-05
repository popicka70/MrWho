using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("Integration")] 
public class AdditionalEndpointNegativeTests
{
    private HttpClient CreateServerClient() => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

    [TestMethod]
    public async Task QrLogin_Status_With_Invalid_Token_Returns_NotFound_Or_Expired()
    {
        using var client = CreateServerClient();
        var resp = await client.GetAsync("qr-login/status?token=does-not-exist-token-xyz");
        var body = await resp.Content.ReadAsStringAsync();
        // Either explicit 404 or JSON with expired flag/status
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.NotFound || body.Contains("expired", StringComparison.OrdinalIgnoreCase) || body.Contains("error", StringComparison.OrdinalIgnoreCase), $"Unexpected response: {(int)resp.StatusCode} {body}");
    }

    [TestMethod]
    public async Task Devices_Api_Requires_Authentication()
    {
        using var client = CreateServerClient();
        var resp = await client.GetAsync("api/devices");
        // Expect 401 (unauthorized) or 302 redirect to login (if cookie auth kicks in)
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Redirect || resp.StatusCode == HttpStatusCode.Forbidden, $"Expected protected status, got {(int)resp.StatusCode}");
    }

    [TestMethod]
    public async Task QrLogin_Start_Returns_Html()
    {
        using var client = CreateServerClient();
        var resp = await client.GetAsync("qr-login/start");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.AreEqual(HttpStatusCode.OK, resp.StatusCode, "start should render view");
        Assert.IsTrue(body.Contains("QR", StringComparison.OrdinalIgnoreCase) || body.Length > 100, "Expected some HTML content for start page");
    }

    [TestMethod]
    public async Task Connect_Token_Invalid_Client_Shows_Error()
    {
        using var client = CreateServerClient();
        var form = new Dictionary<string,string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "invalid_client_xyz",
            ["client_secret"] = "nope"
        };
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.BadRequest || resp.StatusCode == HttpStatusCode.Unauthorized, $"Unexpected status {(int)resp.StatusCode} body: {body}");
    }
}
