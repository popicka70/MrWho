using System.Diagnostics;
using System.Text.Json;
using Aspire.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions; // added (may be unused now but keep if needed elsewhere)

namespace MrWhoAdmin.Tests;

/// <summary>
/// Shared test infrastructure for all integration tests
/// This starts PostgreSQL (via Aspire) once and reuses it across all integration tests
/// </summary>
[TestClass]
public static class SharedTestInfrastructure
{
    private static DistributedApplication? _app;
    private static TimeSpan StartupTimeout => GetStartupTimeout(); // Allow override via env var

    private static TimeSpan GetStartupTimeout()
    {
        var env = Environment.GetEnvironmentVariable("MRWHO_TESTS_STARTUP_TIMEOUT_SECONDS");
        if (int.TryParse(env, out var seconds) && seconds > 0)
        {
            return TimeSpan.FromSeconds(seconds);
        }
        // Default increased timeout for slower machines/CI
        return TimeSpan.FromSeconds(300);
    }

    /// <summary>
    /// Initialize shared infrastructure once for the entire test assembly
    /// </summary>
    [AssemblyInitialize]
    public static async Task AssemblyInitialize(TestContext context)
    {
        Console.WriteLine($"Starting shared PostgreSQL Aspire infrastructure for all integration tests (async)... Timeout: {StartupTimeout}");

        // Signal AppHost that we are in test mode so it provisions Postgres
        Environment.SetEnvironmentVariable("MRWHO_TESTS", "1");
        // Disable HTTPS redirection inside the API during tests to avoid http->https redirect losing Authorization header
        Environment.SetEnvironmentVariable("DISABLE_HTTPS_REDIRECT", "true");

        using var cts = new CancellationTokenSource(StartupTimeout);
        var ct = cts.Token;

        try
        {
            // Create the Aspire application host
            var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(
                Array.Empty<string>(),
                (o, s) =>
                {
                    // Keep original behavior: enforce HTTPS inside test environment
                    o.AllowUnsecuredTransport = false;
                },
                ct);

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
            });

            // Build and start the application
            _app = await appHost.BuildAsync(ct);
            await _app.StartAsync(ct);

            // Wait for resources to be healthy
            await _app.ResourceNotifications.WaitForResourceHealthyAsync("postgres", ct);
            await _app.ResourceNotifications.WaitForResourceHealthyAsync("mrwho", ct);
            await _app.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", ct);

            // Poll the running API instead of trying to resolve its internal DI services from the host.
            // The host ServiceProvider does NOT expose the app's container, so GetService<IOpenIddictApplicationManager>() was always null.
            await WaitForOpenIddictClientAsync("mrwho_admin_web", ct);

            Console.WriteLine("Shared PostgreSQL infrastructure started successfully!");
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Startup cancelled (timeout reached). Tests may fail.");
            throw;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to start shared infrastructure: {ex}");
            throw;
        }
    }

    private static async Task WaitForOpenIddictClientAsync(string clientId, CancellationToken ct)
    {
        try
        {
            Console.WriteLine($"Waiting for OpenIddict client registration via HTTP (client_id={clientId})...");
            var sw = Stopwatch.StartNew();
            var maxWait = TimeSpan.FromSeconds(45);
            var delay = TimeSpan.FromMilliseconds(750);
            bool ready = false;
            var http = GetSharedApp().CreateHttpClient("mrwho", "https");

            while (sw.Elapsed < maxWait && !ct.IsCancellationRequested)
            {
                try
                {
                    using var resp = await http.GetAsync($"debug/openiddict-application?client_id={clientId}", ct);
                    if (resp.IsSuccessStatusCode)
                    {
                        var json = await resp.Content.ReadAsStringAsync(ct);
                        if (!string.IsNullOrWhiteSpace(json))
                        {
                            // basic validation: ensure 'clientId' or 'client_id' present in payload
                            if (json.Contains(clientId, StringComparison.OrdinalIgnoreCase))
                            {
                                ready = true;
                                break;
                            }
                        }
                    }
                }
                catch (HttpRequestException)
                {
                    // ignore until service responds
                }
                await Task.Delay(delay, ct);
            }
            if (!ready)
            {
                Console.WriteLine("Timed out waiting for OpenIddict client registration; tests may still work if not required.");
            }
            else
            {
                Console.WriteLine("OpenIddict client registration detected.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception while polling for OpenIddict client: {ex.Message}");
        }
    }

    /// <summary>
    /// Cleanup shared infrastructure at the end of all tests
    /// </summary>
    [AssemblyCleanup]
    public static async Task AssemblyCleanup()
    {
        if (_app != null)
        {
            Console.WriteLine("Cleaning up shared Aspire infrastructure...");
            await _app.DisposeAsync();
            Console.WriteLine("Shared infrastructure cleanup completed!");
        }
    }

    /// <summary>
    /// Get the shared application instance for tests
    /// </summary>
    public static DistributedApplication GetSharedApp()
    {
        return _app ?? throw new Exception("Not initialized");
    }

    /// <summary>
    /// Create an HTTP client for a specific service.
    /// Optional flags allow disabling redirects and cookies to avoid cross-test auth leakage.
    /// </summary>
    public static HttpClient CreateHttpClient(string serviceName, bool disableRedirects = false, bool disableCookies = false)
    {
        // Use Aspire to get a correctly-based client first (to learn BaseAddress)
        var baseClient = GetSharedApp().CreateHttpClient(serviceName, "https");
        var baseAddress = baseClient.BaseAddress;

        // Fast path: keep Aspire's client when no special behavior requested
        if (!disableRedirects && !disableCookies)
        {
            return baseClient;
        }

        // Otherwise, dispose the initial client and create an isolated handler/client
        baseClient.Dispose();

        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = !disableRedirects,
            UseCookies = !disableCookies,
            ClientCertificateOptions = ClientCertificateOption.Manual,
            // Accept any HTTPS certificate (dev certs) but reject non-HTTPS
            ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => msg?.RequestUri?.Scheme == Uri.UriSchemeHttps
        };

        var client = new HttpClient(handler)
        {
            BaseAddress = baseAddress
        };

        return client;
    }
}
