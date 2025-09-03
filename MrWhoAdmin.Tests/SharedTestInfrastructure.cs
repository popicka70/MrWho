using Microsoft.Extensions.Logging;
using Aspire.Hosting;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Shared test infrastructure for all integration tests
/// This starts PostgreSQL (via Aspire) once and reuses it across all integration tests
/// </summary>
[TestClass]
public static class SharedTestInfrastructure
{
    private static DistributedApplication? _app;
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(180); // Generous timeout for initial startup
    private static readonly object _lock = new object();
    private static bool _isInitialized = false;

    /// <summary>
    /// Initialize shared infrastructure once for the entire test assembly
    /// </summary>
    [AssemblyInitialize]
    public static async Task AssemblyInitialize(TestContext context)
    {
        if (_isInitialized) return;

        lock (_lock)
        {
            if (_isInitialized) return;

            Console.WriteLine("?? Starting shared PostgreSQL Aspire infrastructure for all integration tests...");

            // Signal AppHost that we are in test mode so it provisions Postgres
            Environment.SetEnvironmentVariable("MRWHO_TESTS", "1");

            var cancellationToken = new CancellationTokenSource(StartupTimeout).Token;

            // Create the Aspire application host
            var appHost = DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken).Result;

            appHost.Services.AddLogging(logging =>
            {
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Aspire.", LogLevel.Information);
            });

            // Build and start the application
            _app = appHost.BuildAsync(cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Result;
            _app.StartAsync(cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();

            // Wait for resources to be healthy
            // postgres (server) name derived from AppHost ("postgres") and database reference supplies connection string named mrwhodb
            _app.ResourceNotifications.WaitForResourceHealthyAsync("postgres", cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();
            _app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();
            _app.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();

            _isInitialized = true;
            Console.WriteLine("? Shared PostgreSQL infrastructure started successfully!");
        }
        await Task.CompletedTask; // Ensure method is async
    }

    /// <summary>
    /// Cleanup shared infrastructure at the end of all tests
    /// </summary>
    [AssemblyCleanup]
    public static async Task AssemblyCleanup()
    {
        if (_app != null)
        {
            Console.WriteLine("?? Cleaning up shared Aspire infrastructure...");
            await _app.DisposeAsync();
            Console.WriteLine("? Shared infrastructure cleanup completed!");
        }
    }

    /// <summary>
    /// Get the shared application instance for tests
    /// </summary>
    public static DistributedApplication GetSharedApp()
    {
        if (!_isInitialized || _app == null)
        {
            throw new InvalidOperationException("Shared infrastructure not initialized. Make sure [AssemblyInitialize] ran.");
        }
        return _app;
    }

    /// <summary>
    /// Create an HTTP client for a specific service
    /// </summary>
    public static HttpClient CreateHttpClient(string serviceName)
    {
        return GetSharedApp().CreateHttpClient(serviceName);
    }
}
