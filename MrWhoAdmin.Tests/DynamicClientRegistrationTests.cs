using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("DynamicRegistration")] 
public class DynamicClientRegistrationTests
{
    private static HttpClient CreateServerClient() => SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

    private static async Task<string> GetAdminAccessTokenAsync(string scope = "openid profile email offline_access mrwho.use")
    {
        using var http = CreateServerClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "mrwho_admin_web",
            ["client_secret"] = "MrWhoAdmin2024!SecretKey",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = scope
        };
        var resp = await http.PostAsync("connect/token", new FormUrlEncodedContent(form));
        var body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        if (root.TryGetProperty("access_token", out var at))
        {
            return at.GetString()!;
        }
        Assert.Fail($"Failed to get access token. Status {(int)resp.StatusCode}. Body: {body}");
        return string.Empty;
    }

    private static void SetBearer(HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    [TestMethod]
    public async Task Register_Client_As_Pending_Then_Approve_Creates_Client()
    {
        // 1) Acquire admin access token
        var token = await GetAdminAccessTokenAsync();

        // 2) Submit dynamic registration
        using var http = CreateServerClient();
        SetBearer(http, token);

        var regPayload = new
        {
            client_name = "dyn_demo_app",
            grant_types = new[] { "authorization_code" },
            response_types = new[] { "code" },
            redirect_uris = new[] { "https://localhost:5003/callback" },
            post_logout_redirect_uris = new[] { "https://localhost:5003/" },
            scope = "openid profile email"
        };
        var regJson = JsonSerializer.Serialize(regPayload);
        var regResp = await http.PostAsync("connect/register", new StringContent(regJson, Encoding.UTF8, "application/json"));
        var regBody = await regResp.Content.ReadAsStringAsync();
        Assert.AreEqual(System.Net.HttpStatusCode.Accepted, regResp.StatusCode, $"Expected 202. Body: {regBody}");
        using var regDoc = JsonDocument.Parse(regBody);
        var regId = regDoc.RootElement.GetProperty("registration_id").GetString();
        Assert.IsFalse(string.IsNullOrWhiteSpace(regId), "registration_id missing");

        // 3) List pending and ensure the registration is present
        var pendingResp = await http.GetAsync("api/client-registrations/pending?page=1&pageSize=50");
        var pendingBody = await pendingResp.Content.ReadAsStringAsync();
        Assert.IsTrue(pendingResp.IsSuccessStatusCode, $"Pending failed. Body: {pendingBody}");
        using var pendingDoc = JsonDocument.Parse(pendingBody);
        var items = pendingDoc.RootElement.GetProperty("items").EnumerateArray().ToList();
        Assert.IsTrue(items.Any(it => string.Equals(it.GetProperty("id").GetString(), regId, StringComparison.OrdinalIgnoreCase)), "Pending list does not contain submitted registration");

        // 4) Approve registration
        var approveResp = await http.PostAsync($"api/client-registrations/{regId}/approve", null);
        var approveBody = await approveResp.Content.ReadAsStringAsync();
        Assert.IsTrue(approveResp.IsSuccessStatusCode, $"Approve failed. Body: {approveBody}");
        using var approveDoc = JsonDocument.Parse(approveBody);
        var clientId = approveDoc.RootElement.TryGetProperty("client_id", out var cid) ? cid.GetString() : null;
        Assert.IsFalse(string.IsNullOrWhiteSpace(clientId), $"client_id missing in approval result. Body: {approveBody}");

        // 5) Verify OpenIddict app exists via debug endpoint
        var debugResp = await http.GetAsync($"debug/openiddict-application?client_id={clientId}");
        var debugBody = await debugResp.Content.ReadAsStringAsync();
        Assert.IsTrue(debugResp.IsSuccessStatusCode, $"Debug OpenIddict application not found. Body: {debugBody}");
        using var debugDoc = JsonDocument.Parse(debugBody);
        var dbg = debugDoc.RootElement;
        Assert.IsTrue(dbg.TryGetProperty("clientId", out var dbgClientId) || debugBody.Contains(clientId!, StringComparison.OrdinalIgnoreCase), "client not present in debug payload");
    }

    [TestMethod]
    public async Task Register_Client_Then_Reject_Marks_As_Rejected()
    {
        var token = await GetAdminAccessTokenAsync();
        using var http = CreateServerClient();
        SetBearer(http, token);

        var regPayload = new
        {
            client_name = "dyn_demo_reject",
            grant_types = new[] { "client_credentials" },
            scope = "api.read"
        };
        var regResp = await http.PostAsync("connect/register", new StringContent(JsonSerializer.Serialize(regPayload), Encoding.UTF8, "application/json"));
        var regBody = await regResp.Content.ReadAsStringAsync();
        Assert.AreEqual(System.Net.HttpStatusCode.Accepted, regResp.StatusCode, $"Expected 202. Body: {regBody}");
        var regId = JsonDocument.Parse(regBody).RootElement.GetProperty("registration_id").GetString();
        Assert.IsFalse(string.IsNullOrWhiteSpace(regId));

        // Reject with reason
        var rejectResp = await http.PostAsync($"api/client-registrations/{regId}/reject", new StringContent(JsonSerializer.Serialize(new { reason = "Not permitted" }), Encoding.UTF8, "application/json"));
        var rejectBody = await rejectResp.Content.ReadAsStringAsync();
        Assert.IsTrue(rejectResp.IsSuccessStatusCode, $"Reject failed. Body: {rejectBody}");

        // Verify details show processed (either status rejected or not pending anymore)
        var detailsResp = await http.GetAsync($"api/client-registrations/{regId}");
        var detailsBody = await detailsResp.Content.ReadAsStringAsync();
        Assert.IsTrue(detailsResp.IsSuccessStatusCode, $"Details fetch failed. Body: {detailsBody}");
        using var detailsDoc = JsonDocument.Parse(detailsBody);
        var root = detailsDoc.RootElement;
        // Status could be numeric (enum) or string depending on serialization; accept either rejected or 2
        bool rejected = (root.TryGetProperty("Status", out var s1) && (s1.ValueKind == JsonValueKind.String ? string.Equals(s1.GetString(), "Rejected", StringComparison.OrdinalIgnoreCase) : s1.GetInt32() == 2))
                        || (root.TryGetProperty("status", out var s2) && (s2.ValueKind == JsonValueKind.String ? string.Equals(s2.GetString(), "rejected", StringComparison.OrdinalIgnoreCase) : s2.GetInt32() == 2));
        Assert.IsTrue(rejected, $"Expected rejected status. Body: {detailsBody}");
    }
}
