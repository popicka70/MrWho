using System.Net;
using System.Text.Json;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Verifies password grant availability only in test environment (MRWHO_TESTS=1) per server configuration.
/// </summary>
[TestClass]
[TestCategory("OIDC")] 
public class PasswordGrantConditionalTests
{
    private async Task<HttpStatusCode> RequestPasswordGrantAsync()
    {
        using var client = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);
        var form = new Dictionary<string,string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "postman_client",
            ["client_secret"] = "postman_secret",
            ["username"] = "admin@mrwho.local",
            ["password"] = "Adm1n#2025!G7x",
            ["scope"] = "openid profile"
        };
        var resp = await client.PostAsync("connect/token", new FormUrlEncodedContent(form));
        return resp.StatusCode;
    }

    [TestMethod]
    public async Task Password_Grant_Works_In_Test_Environment()
    {
        // Environment variable MRWHO_TESTS=1 set in SharedTestInfrastructure
        var status = await RequestPasswordGrantAsync();
        status.Should().Be(HttpStatusCode.OK, "password grant should be enabled in test environment");
    }
}
