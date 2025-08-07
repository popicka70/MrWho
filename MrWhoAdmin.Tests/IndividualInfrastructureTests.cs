using Microsoft.Extensions.DependencyInjection;
using MrWho.Data;
using Microsoft.EntityFrameworkCore;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Legacy individual tests - these will be slower but more isolated
/// Use these only when you need complete isolation between tests
/// </summary>
[TestClass]
[TestCategory("Integration-Individual")]
public class IndividualInfrastructureTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Example of a test that needs its own infrastructure
    /// (Only use this pattern when absolutely necessary)
    /// </summary>
    [TestMethod]
    public async Task SlowTest_WithIndividualInfrastructure_WhenIsolationRequired()
    {
        // Arrange - Start individual infrastructure (slow)
        var cancellationToken = new CancellationTokenSource(DefaultTimeout).Token;
        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        
        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        await app.ResourceNotifications.WaitForResourceHealthyAsync("sqlserver", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Act
        var httpClient = app.CreateHttpClient("mrwho");
        var response = await httpClient.GetAsync("/api/realms");

        // Assert
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Unauthorized);
    }
}