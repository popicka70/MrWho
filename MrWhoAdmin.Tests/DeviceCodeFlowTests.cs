using System.Net;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class DeviceCodeFlowTests
{
    private static HttpClient CreateServerClient(bool disableRedirects = true) => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: disableRedirects);

    private static async Task<JsonDocument> PostAsync(string url, Dictionary<string, string> form)
    {
        using var client = CreateServerClient();
        var resp = await client.PostAsync(url, new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        try { return JsonDocument.Parse(body); } catch { Assert.Fail($"Non JSON response: {(int)resp.StatusCode} {body}"); throw; }
    }

    [TestMethod]
    public async Task Device_Authorization_And_Token_Polling_Pending()
    {
        using var deviceDoc = await PostAsync("connect/device", new Dictionary<string, string>
        {
            ["client_id"] = "mrwho_admin_web",
            ["scope"] = "openid profile"
        });
        var root = deviceDoc.RootElement;
        if (root.TryGetProperty("error", out var err))
        {
            Assert.Inconclusive($"Device endpoint error: {err.GetString()} {root}");
        }

        var deviceCode = root.GetProperty("device_code").GetString();
        Assert.IsFalse(string.IsNullOrEmpty(deviceCode));

        using var poll = await PostAsync("connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["device_code"] = deviceCode!,
            ["client_id"] = "mrwho_admin_web"
        });
        var pollRoot = poll.RootElement;
        Assert.IsTrue(pollRoot.TryGetProperty("error", out var pollErr), "Expected error while pending");
        var code = pollErr.GetString();
        Assert.IsTrue(code is "authorization_pending" or "slow_down", $"Unexpected interim error: {code}");
    }
}
