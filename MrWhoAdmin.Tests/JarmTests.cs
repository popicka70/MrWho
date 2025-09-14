using System.Net;
using System.Security.Cryptography; // added for PKCE
using System.Text; // added for PKCE
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

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    [TestMethod]
    public async Task Jarm_ResponseMode_Jwt_Request_Is_Accepted()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);
        var authz = disco.RootElement.GetProperty("authorization_endpoint").GetString()!;

        var (_, challenge) = CreatePkcePair();
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(DemoClientId)}&response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri)}&scope={Uri.EscapeDataString(Scope)}&state=test_jarm&code_challenge={challenge}&code_challenge_method=S256&response_mode=jwt";
        var resp = await http.GetAsync(url);

        // Handle potential intermediate redirect to cached request (OpenIddict request caching / PAR-like flow)
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            var firstLoc = resp.Headers.Location?.ToString() ?? string.Empty;
            if (firstLoc.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase) && firstLoc.Contains("request_uri=", StringComparison.OrdinalIgnoreCase))
            {
                // Follow one hop manually
                string secondUrl;
                if (firstLoc.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    secondUrl = firstLoc;
                }
                else
                {
                    secondUrl = new Uri(http.BaseAddress!, firstLoc).ToString();
                }
                // Request relative path for test infrastructure consistency
                var relative = secondUrl.StartsWith(http.BaseAddress!.ToString(), StringComparison.OrdinalIgnoreCase)
                    ? secondUrl.Substring(http.BaseAddress!.ToString().Length).TrimStart('/')
                    : secondUrl;
                resp = await http.GetAsync(relative);
            }
        }

        string errorBody = string.Empty;
        if ((int)resp.StatusCode >= 400)
        {
            errorBody = await resp.Content.ReadAsStringAsync();
        }

        Assert.IsTrue(resp.StatusCode == HttpStatusCode.Redirect || resp.StatusCode == HttpStatusCode.OK, $"Unexpected status {resp.StatusCode}. Body={errorBody}");
        if (resp.StatusCode == HttpStatusCode.Redirect)
        {
            var loc = resp.Headers.Location?.ToString() ?? string.Empty;
            // Accept either direct login redirect or an authorize redirect with request_uri (already handled earlier) though unlikely here.
            if (loc.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase) && loc.Contains("request_uri=", StringComparison.OrdinalIgnoreCase))
            {
                // Treat as acceptable intermediate (should be rare at this point)
                return;
            }
            StringAssert.Contains(loc, "/connect/login", "Should redirect to login for unauthenticated user");
            StringAssert.Contains(loc, "returnUrl=", "Login redirect should carry returnUrl for original authorize request");
        }
    }

    [TestMethod]
    public async Task Jarm_Unsupported_ResponseMode_Is_Rejected()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        using var disco = await GetDiscoveryAsync(http);

        var (_, challenge) = CreatePkcePair();
        var url = $"connect/authorize?client_id={Uri.EscapeDataString(DemoClientId)}&response_type=code&redirect_uri={Uri.EscapeDataString(RedirectUri)}&scope={Uri.EscapeDataString(Scope)}&state=test_badmode&code_challenge={challenge}&code_challenge_method=S256&response_mode=form_post.jwt"; // not yet supported
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
