using System.Net;
using System.Text;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")]
public class PasswordGrantAndRefreshFlowTests
{
    private static HttpClient CreateServerClient() => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

    private static async Task<JsonDocument> PostTokenAsync(Dictionary<string, string> form)
    {
        using var client = CreateServerClient();
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        try
        {
            return JsonDocument.Parse(body);
        }
        catch
        {
            Assert.Fail($"Token endpoint did not return JSON. Status {(int)resp.StatusCode}. Body: {body}");
            throw; // unreachable
        }
    }

    [TestMethod]
    public async Task PasswordGrant_AdminClient_Succeeds_Returns_RefreshToken()
    {
        // admin client allows password flow when MRWHO_TESTS=1 env var is set by test infrastructure
        var doc = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = "openid profile email offline_access mrwho.use"
        });

        var root = doc.RootElement;
        Assert.IsFalse(root.TryGetProperty("error", out var _), $"Unexpected error response: {root}");
        Assert.IsTrue(root.TryGetProperty("access_token", out var access));
        Assert.IsTrue(root.TryGetProperty("refresh_token", out var refresh));
        Assert.IsTrue(access.GetString()!.Length > 20, "Access token too short");
        Assert.IsTrue(refresh.GetString()!.Length > 20, "Refresh token missing/short");
    }

    [TestMethod]
    public async Task PasswordGrant_Demo1Client_Fails()
    {
        // demo1 client explicitly disallows password flow
        var doc = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_demo1",
            ["client_secret"] = "PyfrZln6d2ifAbdL_2gr316CERUMyzfpgmxJ1J3xJsWUnfHGakcvjWenB_OwQqnv",
            ["username"] = "demo1@example.com",
            ["password"] = "Dem0!User#2025",
            ["scope"] = "openid profile email offline_access"
        });
        var root = doc.RootElement;
        // Expect error element
        Assert.IsTrue(root.TryGetProperty("error", out var errorProp), "Expected error for disallowed password grant");
        var err = errorProp.GetString();
        // Typically invalid_grant or unauthorized_client depending on server validation ordering
        Assert.IsTrue(err == "invalid_grant" || err == "unauthorized_client" || err == "unsupported_grant_type", $"Unexpected error: {err}");
    }

    [TestMethod]
    public async Task RefreshToken_Flow_Issues_New_AccessToken()
    {
        // Initial password grant for admin client
        var initial = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = "openid profile email offline_access mrwho.use"
        });
        var access1 = initial.RootElement.GetProperty("access_token").GetString()!;
        var refresh = initial.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.IsFalse(string.IsNullOrEmpty(refresh), "Initial refresh token missing");

        // Exchange refresh token
        var refreshed = await PostTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["refresh_token"] = refresh
        });
        if (refreshed.RootElement.TryGetProperty("error", out var errProp))
        {
            Assert.Fail($"Refresh token exchange failed: {errProp.GetString()} {refreshed.RootElement}");
        }
        Assert.IsTrue(refreshed.RootElement.TryGetProperty("access_token", out var access2Prop));
        var access2 = access2Prop.GetString()!;
        Assert.IsTrue(access2.Length > 20, "Refreshed access token too short");
        // Depending on rolling refresh configuration, tokens may or may not differ; just ensure valid token returned
    }
}
