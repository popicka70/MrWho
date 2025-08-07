using Aspire.Hosting;
using MrWhoAdmin.Tests;
using MrWhoAdmin.Web.Components;

[TestClass]
[TestCategory("Integration")]
public class OptimizedWebTests
{
    private static DistributedApplication? _sharedApp;
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(180);

    [ClassInitialize]
    public static async Task ClassInitialize(TestContext context)
    {
        Console.WriteLine("🚀 Starting shared MSSQL for WebTests class...");

        var cancellationToken = new CancellationTokenSource(StartupTimeout).Token;
        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);

        _sharedApp = SharedTestInfrastructure.GetSharedApp();

        await _sharedApp.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", cancellationToken).WaitAsync(StartupTimeout, cancellationToken);

        Console.WriteLine("✅ Shared MSSQL ready for all tests!");
    }

    [ClassCleanup]
    public static async Task ClassCleanup()
    {
        if (_sharedApp != null)
        {
            await _sharedApp.DisposeAsync();
        }
    }

    [TestMethod]
    public async Task GetWebResourceRoot_ReturnsOk_UsingSharedInfrastructure()
    {
        // Arrange - Use shared infrastructure (NO startup time!)
        using var httpClient = _sharedApp!.CreateHttpClient("webfrontend");

        // Act
        var response = await httpClient.GetAsync("/");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [TestMethod]
    public async Task DatabaseIntegration_WorksCorrectly_UsingSharedInfrastructure()
    {
        // Arrange - Use shared infrastructure (NO startup time!)
        using var httpClient = _sharedApp!.CreateHttpClient("webfrontend");

        // Act
        var response = await httpClient.GetAsync("/api/realms?page=1&pageSize=10");

        // Assert
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }

    [TestMethod]
    public async Task MultipleServices_WorkTogether_UsingSharedInfrastructure()
    {
        // Arrange - Test both services with shared infrastructure
        using var webClient = _sharedApp!.CreateHttpClient("webfrontend");
        using var apiClient = _sharedApp!.CreateHttpClient("mrwho");

        // Act
        var webResponse = await webClient.GetAsync("/");
        var apiResponse = await apiClient.GetAsync("/api/realms");

        // Assert
        webResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        apiResponse.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }
}