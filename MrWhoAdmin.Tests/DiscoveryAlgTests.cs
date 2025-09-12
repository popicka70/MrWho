using System.Text.Json;

namespace MrWhoAdmin.Tests;

[TestClass]
public class DiscoveryAlgTests
{
    [TestMethod]
    public async Task Discovery_Excludes_HS_Algs_When_No_Jar_Clients_Need_Them()
    {
        using var http = SharedTestInfrastructure.CreateHttpClient("mrwho", disableRedirects: true);

        // Fetch discovery
        using var disco = await http.GetAsync(".well-known/openid-configuration");
        disco.EnsureSuccessStatusCode();
        var json = await disco.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.IsTrue(root.TryGetProperty("request_object_signing_alg_values_supported", out var algsProp), "Discovery missing alg list");
        var list = algsProp.EnumerateArray().Select(e => e.GetString()!).ToList();

        // Assumption: initial test data registers only RS256 (and optionally HS256 via defaults). If HS256 not explicitly present, ensure HS384/HS512 absent.
        Assert.IsFalse(list.Contains("HS384"), "HS384 should not be advertised without a client requiring it");
        Assert.IsFalse(list.Contains("HS512"), "HS512 should not be advertised without a client requiring it");
    }
}
