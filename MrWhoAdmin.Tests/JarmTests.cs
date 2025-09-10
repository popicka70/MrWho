using System.Net;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")] 
public class JarmTests
{
    private const string DemoClientId = "mrwho_demo1";
    private const string RedirectUri = "https://localhost:7037/signin-oidc";
    private const string Scope = "openid profile email";

    private static async Task<JsonDocument> GetDiscoveryAsync(HttpClient http)
    {
        using var resp = await http.GetAsync(".well-known/openid-configuration");
        resp.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }

    [TestMethod]
    public async Task Jarm_ResponseMode_Jwt_Request_Is_Accepted()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;

        // Build standard authorization request with response_mode=jwt (no JAR yet for simplicity)
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(DemoClientId)}&response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri)}&scope={Uri.EscapeDataString(Scope)}&state=test_jarm&response_mode=jwt";
        var resp = await http.GetAsync(url);

        // Pre-auth stage should redirect to login OR display login page (200). Must not be a protocol error (>=400)
        Assert.IsTrue(resp.StatusCode == HttpStatusCode.Redirect || resp.StatusCode == HttpStatusCode.OK, $"Unexpected status {resp.StatusCode}");
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            StringAssert.Contains(loc, "/connect/login", "Should redirect to login for unauthenticated user");
            StringAssert.Contains(loc, "returnUrl=", "Login redirect should carry returnUrl for original authorize request");
        }
    }

    [TestMethod]
    public async Task Jarm_Unsupported_ResponseMode_Is_Rejected()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);

        var url = $"connect/authorize?client_id={Uri.EscapeDataString(DemoClientId)}&response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri)}&scope={Uri.EscapeDataString(Scope)}&state=test_badmode&response_mode=form_post.jwt"; // not yet supported
        var resp = await http.GetAsync(url);

        // Expect either 400 error or silent fallback (treat as unsupported) -> if redirect occurs it's a failure of enforcement; allow >=400 as pass.
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            Assert.Fail($"Unsupported JARM response mode resulted in redirect (should be rejected/future fallback). Location={resp.Headers.Location}");
        }
        Assert.IsTrue((int)resp.StatusCode >= 400, $"Expected error for unsupported response_mode, got {resp.StatusCode}");
    }

    // Placeholder for future full JARM issuance test post-authentication
    // Will need: programmatic login (session/cookies) then authorize with response_mode=jwt and validate 'response' JWT claims (iss,aud,iat,exp,code,state)
}
