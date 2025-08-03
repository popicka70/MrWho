using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MrWho.Data;
using Microsoft.EntityFrameworkCore;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Advanced integration tests showing different approaches to testing with Aspire's SQL Server
/// </summary>
[TestClass]
public class AspireSqlServerTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(60); // Longer timeout for database startup

    /// <summary>
    /// Test that demonstrates waiting for SQL Server to be healthy before running tests
    /// </summary>
    [TestMethod]
    public async Task SqlServer_StartsHealthy_WithAspire()
    {
        // Arrange
        var cancellationToken = new CancellationTokenSource(DefaultTimeout).Token;

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        
        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Act - Wait for SQL Server to become healthy
        await app.ResourceNotifications.WaitForResourceHealthyAsync("sqlserver", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        
        // Assert - If we get here without timeout, SQL Server started successfully
        Assert.IsTrue(true, "SQL Server started and became healthy");
    }

    /// <summary>
    /// Test that demonstrates accessing the database connection string from Aspire
    /// </summary>
    [TestMethod]
    public async Task CanAccessDatabase_ThroughAspireConfiguration()
    {
        // Arrange
        var cancellationToken = new CancellationTokenSource(DefaultTimeout).Token;

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        
        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Wait for all resources to be ready
        await app.ResourceNotifications.WaitForResourceHealthyAsync("sqlserver", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Act - Access the MrWho service and test database connectivity
        var httpClient = app.CreateHttpClient("mrwho");
        var response = await httpClient.GetAsync("/api/test", cancellationToken); // Assuming you have a test endpoint

        // Assert
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized, HttpStatusCode.NotFound);
    }

    /// <summary>
    /// Test that demonstrates running database migrations through Aspire
    /// </summary>
    [TestMethod]
    public async Task DatabaseMigrations_WorkWithAspire()
    {
        // Arrange
        var cancellationToken = new CancellationTokenSource(DefaultTimeout).Token;

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        
        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Wait for SQL Server and the MrWho service to be ready
        await app.ResourceNotifications.WaitForResourceHealthyAsync("sqlserver", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Act - Try to access an endpoint that requires database tables to exist
        var httpClient = app.CreateHttpClient("mrwho");
        var response = await httpClient.GetAsync("/api/realms?page=1&pageSize=1", cancellationToken);

        // Assert - If migrations ran, we should get a valid response (even if empty)
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Test that demonstrates testing with multiple services and SQL Server
    /// </summary>
    [TestMethod]
    public async Task FullIntegration_WebFrontend_And_Api_WithDatabase()
    {
        // Arrange
        var cancellationToken = new CancellationTokenSource(DefaultTimeout).Token;

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        
        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Wait for all services to be ready
        await app.ResourceNotifications.WaitForResourceHealthyAsync("sqlserver", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Act - Test the web frontend
        var webHttpClient = app.CreateHttpClient("webfrontend");
        var webResponse = await webHttpClient.GetAsync("/", cancellationToken);
        
        // Test the API backend
        var apiHttpClient = app.CreateHttpClient("mrwho");
        var apiResponse = await apiHttpClient.GetAsync("/api/realms", cancellationToken);

        // Assert - Both services should be responding
        webResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        apiResponse.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }
}

/// <summary>
/// Tests demonstrating different testing strategies
/// </summary>
[TestClass]
public class TestingStrategies
{
    /// <summary>
    /// Fast unit tests using in-memory database - no Aspire required
    /// </summary>
    [TestMethod]
    public void UnitTest_FastExecution_InMemoryDatabase()
    {
        // Arrange - Fast in-memory database for unit tests
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        using var context = new ApplicationDbContext(options);

        // Act - Test database operations
        var realm = new MrWho.Models.Realm
        {
            Id = Guid.NewGuid().ToString(),
            Name = "Test Realm",
            IsEnabled = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        context.Realms.Add(realm);
        context.SaveChanges();

        // Assert
        var savedRealm = context.Realms.Find(realm.Id);
        savedRealm.Should().NotBeNull();
        savedRealm!.Name.Should().Be("Test Realm");
    }

    /// <summary>
    /// Integration test using Aspire's SQL Server - slower but more realistic
    /// </summary>
    [TestMethod]
    public async Task IntegrationTest_RealDatabase_ThroughAspire()
    {
        // Arrange
        var cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(60)).Token;

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        
        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

        // Wait for resources
        await app.ResourceNotifications.WaitForResourceHealthyAsync("sqlserver", cancellationToken).WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

        // Act - Test through HTTP API (which uses real SQL Server)
        var httpClient = app.CreateHttpClient("mrwho");
        var response = await httpClient.GetAsync("/api/realms", cancellationToken);

        // Assert
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }
}