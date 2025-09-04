namespace MrWhoAdmin.Tests;

/// <summary>
/// Optimized integration tests using shared MSSQL infrastructure
/// </summary>
[TestClass]
[TestCategory("Integration")]
public class OptimizedIntegrationTests
{
    /// <summary>
    /// Test that the shared App is healthy and accessible
    /// </summary>
    [TestMethod]
    public void SharedApp_IsHealthy()
    {
        // Arrange & Act
        var app = SharedTestInfrastructure.GetSharedApp();

        // Assert - If we get here, the shared infrastructure is working
        app.Should().NotBeNull();
    }

    /// <summary>
    /// Test API backend using shared infrastructure
    /// </summary>
    [TestMethod]
    public async Task ApiBackend_ReturnsValidResponse_UsingSharedInfrastructure()
    {
        // Arrange
        using var httpClient = SharedTestInfrastructure.CreateHttpClient("mrwho");

        // Act
        var response = await httpClient.GetAsync("/api/realms?page=1&pageSize=5");

        // Assert
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Test database operations using shared infrastructure
    /// </summary>
    [TestMethod]
    public async Task Database_SupportsOperations_UsingSharedInfrastructure()
    {
        // Arrange
        using var httpClient = SharedTestInfrastructure.CreateHttpClient("mrwho");

        // Act - Test multiple database operations
        var realmsResponse = await httpClient.GetAsync("/api/realms");
        var testResponse = await httpClient.GetAsync("/api/test");

        // Assert
        realmsResponse.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
        testResponse.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized, HttpStatusCode.NotFound);
    }
}
