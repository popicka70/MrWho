using Microsoft.Extensions.Logging;
using Aspire.Hosting;
using OpenIddict.Abstractions; // added

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
            // Disable HTTPS redirection inside the API during tests to avoid http->https redirect losing Authorization header
            Environment.SetEnvironmentVariable("DISABLE_HTTPS_REDIRECT", "true");

            var cancellationToken = new CancellationTokenSource(StartupTimeout).Token;

            // Create the Aspire application host
            var appHost = DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(new string[] {}, 
            (o, s) => {
                o.AllowUnsecuredTransport = false; // enforce HTTPS
            }, cancellationToken).Result;

            appHost.Services.AddLogging(logging =>
            {
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Aspire.", LogLevel.Information);
            });

            appHost.Services.ConfigureHttpClientDefaults(http =>
            {
                http.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
                {
                    ClientCertificateOptions = ClientCertificateOption.Manual,
                    ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) =>
                    {
                        // Only allow HTTPS connections
                        return httpRequestMessage.RequestUri?.Scheme == Uri.UriSchemeHttps;
                    }
                });

                http.AddHttpMessageHandler(() => new HttpsEnforcementHandler());
            });

            // Build and start the application
            _app = appHost.BuildAsync(cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Result;
            _app.StartAsync(cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();

            // Wait for resources to be healthy
            // postgres (server) name derived from AppHost ("postgres") and database reference supplies connection string named mrwhodb
            _app.ResourceNotifications.WaitForResourceHealthyAsync("postgres", cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();
            _app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();
            _app.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", cancellationToken).WaitAsync(StartupTimeout, cancellationToken).Wait();

            // After services are healthy, poll until the admin OpenIddict application is registered
            try
            {
                Console.WriteLine("? Waiting for OpenIddict admin client registration (mrwho_admin_web)...");
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var maxWait = TimeSpan.FromSeconds(45);
                var delay = TimeSpan.FromMilliseconds(500);
                bool ready = false;
                while (sw.Elapsed < maxWait)
                {
                    using var scope = _app.Services.CreateScope();
                    var mgr = scope.ServiceProvider.GetService<IOpenIddictApplicationManager>();
                    if (mgr != null)
                    {
                        var appReg = mgr.FindByClientIdAsync("mrwho_admin_web").GetAwaiter().GetResult();
                        if (appReg != null)
                        {
                            ready = true;
                            break;
                        }
                    }
                    Thread.Sleep(delay);
                }
                if (!ready)
                {
                    Console.WriteLine("?? Timed out waiting for OpenIddict admin client registration; tests may fail with invalid_client.");
                }
                else
                {
                    Console.WriteLine("? OpenIddict admin client registration detected.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"?? Exception while waiting for OpenIddict readiness: {ex.Message}");
            }

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
    /// Create an HTTP client for a specific service. Set disableRedirects=true to preserve Authorization header.
    /// </summary>
    public static HttpClient CreateHttpClient(string serviceName, bool disableRedirects = false)
    {
        var client = GetSharedApp().CreateHttpClient(serviceName, "https");
        if (!disableRedirects)
            return client;

        // Build a new handler chain with redirects disabled, copying base address
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            // Accept self-signed dev certificates in test environment
            ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
        };
        var newClient = new HttpClient(handler)
        {
            BaseAddress = client.BaseAddress
        };
        foreach (var header in client.DefaultRequestHeaders)
        {
            newClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value);
        }
        return newClient;
    }
}

public class HttpsEnforcementHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri?.Scheme != Uri.UriSchemeHttps)
        {
            // Rewrite the URL to use HTTPS
            var httpsUri = new UriBuilder(request.RequestUri!)
            {
                Scheme = Uri.UriSchemeHttps,
                Port = request.RequestUri!.Port == 80 ? 443 : request.RequestUri.Port
            }.Uri;

            request.RequestUri = httpsUri;
        }

        return await base.SendAsync(request, cancellationToken);
    }
}