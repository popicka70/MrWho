using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class DemoClientPermissionsTests
{
    private async Task<JsonDocument> GetOpenIddictApplicationAsync(string clientId)
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var resp = await http.GetAsync($"debug/openiddict-application?client_id={clientId}");
        var body = await resp.Content.ReadAsStringAsync();
        Assert.IsTrue(resp.IsSuccessStatusCode, $"Expected success fetching openiddict application for {clientId}. Status {(int)resp.StatusCode}. Body: {body}");
        return JsonDocument.Parse(body);
    }

    [TestMethod]
    public async Task Demo1_Client_Has_Authorization_Code_And_RefreshToken_Flows()
    {
        using var doc = await GetOpenIddictApplicationAsync("mrwho_demo1");
        var root = doc.RootElement;
        Assert.IsTrue(root.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Array, "permissions array missing");
        var list = perms.EnumerateArray().Select(e => e.GetString() ?? string.Empty).ToList();

        bool Has(params string[] targets) => list.Any(p => targets.Contains(p, StringComparer.OrdinalIgnoreCase));

        Assert.IsTrue(Has("endpoints.authorization", "ept:authorization"), "authorization endpoint permission missing");
        Assert.IsTrue(Has("endpoints.token", "ept:token"), "token endpoint permission missing");
        Assert.IsTrue(Has("endpoints.end_session", "ept:end_session"), "end session permission missing");
        Assert.IsTrue(Has("grant_types.authorization_code", "gt:authorization_code"), "authorization_code grant missing");
        Assert.IsTrue(Has("grant_types.refresh_token", "gt:refresh_token"), "refresh_token grant missing");
        Assert.IsFalse(Has("grant_types.client_credentials", "gt:client_credentials"), "client_credentials grant should not be enabled for demo1 client");

        // Scope style may vary (scp:offline_access or oidc:scope:offline_access depending on version) - allow either modern or any entry containing offline_access
        Assert.IsTrue(list.Any(p => p.EndsWith("offline_access", StringComparison.OrdinalIgnoreCase)), "offline_access scope permission missing");
    }

    [TestMethod]
    public async Task Demo1_Client_Does_Not_Expose_Password_Grant()
    {
        using var doc = await GetOpenIddictApplicationAsync("mrwho_demo1");
        var list = doc.RootElement.GetProperty("permissions").EnumerateArray().Select(e => e.GetString() ?? string.Empty).ToList();
        Assert.IsFalse(list.Any(p => p.Equals("grant_types.password", StringComparison.OrdinalIgnoreCase) || p.Equals("gt:password", StringComparison.OrdinalIgnoreCase)), "Password grant should not be enabled for demo1 client");
    }
}
