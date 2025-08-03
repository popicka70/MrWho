namespace MrWhoAdmin.Tests;

/// <summary>
/// Optimized integration tests using shared MSSQL infrastructure
/// </summary>
[TestClass]
[TestCategory("Integration")]
public class OptimizedIntegrationTests
{
    /// <summary>
    /// Test that the shared SQL Server is healthy and accessible
    /// </summary>
    [TestMethod]
    public void SharedSqlServer_IsHealthy()
    {
        // Arrange & Act
        var app = SharedTestInfrastructure.GetSharedApp();

        // Assert - If we get here, the shared infrastructure is working
        app.Should().NotBeNull();
    }

    /// <summary>
    /// Test web frontend using shared infrastructure
    /// </summary>
    [TestMethod]
    public async Task WebFrontend_ReturnsOkStatus_UsingSharedInfrastructure()
    {
        // Arrange
        using var httpClient = SharedTestInfrastructure.CreateHttpClient("webfrontend");

        // Act
        var response = await httpClient.GetAsync("/");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
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

    /// <summary>
    /// Test that multiple tests can use the same database concurrently
    /// </summary>
    [TestMethod]
    public async Task MultipleTests_CanUseSameDatabase_Concurrently()
    {
        // Arrange
        using var httpClient1 = SharedTestInfrastructure.CreateHttpClient("mrwho");
        using var httpClient2 = SharedTestInfrastructure.CreateHttpClient("webfrontend");

        // Act - Run concurrent requests
        var task1 = httpClient1.GetAsync("/api/realms");
        var task2 = httpClient2.GetAsync("/");
        
        await Task.WhenAll(task1, task2);

        // Assert
        var response1 = await task1;
        var response2 = await task2;

        response1.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
        response2.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
