using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ServiceDiscovery;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources; // added
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.GoogleCloudLogging; // Added for GoogleCloudLogging sink

namespace Microsoft.Extensions.Hosting;

// Adds common .NET Aspire services: service discovery, resilience, health checks, and OpenTelemetry.
// This project should be referenced by each service project in your solution.
// To learn more about using this project, see https://aka.ms/dotnet/aspire/service-defaults
public static class Extensions
{
    private const string HealthEndpointPath = "/health";
    private const string AlivenessEndpointPath = "/alive";

    public static TBuilder AddServiceDefaults<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        builder.ConfigureSerilog();
        builder.ConfigureOpenTelemetry(); // enable OTEL (was commented out)

        builder.AddDefaultHealthChecks();

        builder.Services.AddServiceDiscovery();

        builder.Services.ConfigureHttpClientDefaults(http =>
        {
            // Turn on resilience by default
            http.AddStandardResilienceHandler();

            // Turn on service discovery by default
            http.AddServiceDiscovery();
        });

        return builder;
    }

    public static TBuilder ConfigureOpenTelemetry<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        // Configure log export (structured) + Activity context
        builder.Logging.AddOpenTelemetry(logging =>
        {
            logging.IncludeFormattedMessage = true;
            logging.IncludeScopes = true;
        });

        // Shared resource describing this service
        var resourceBuilder = ResourceBuilder.CreateEmpty().AddService(serviceName: builder.Environment.ApplicationName, serviceVersion: typeof(Extensions).Assembly.GetName().Version?.ToString() ?? "1.0.0");

        // Configuration-driven EF instrumentation detail level (Default | Commands | All)
        var efVerbosity = builder.Configuration["Telemetry:EntityFramework:Level"] ?? "Default";

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(rb => rb.AddService(builder.Environment.ApplicationName)) // simple name
            .WithMetrics(metrics =>
            {
                metrics
                    .AddRuntimeInstrumentation()
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddMeter("MrWho.Logout"); // custom back-channel logout counters
            })
            .WithTracing(tracing =>
            {
                tracing
                    .SetResourceBuilder(resourceBuilder)
                    .AddSource(builder.Environment.ApplicationName)
                    .AddAspNetCoreInstrumentation(options =>
                    {
                        // Exclude health probes
                        options.Filter = context =>
                            !context.Request.Path.StartsWithSegments(HealthEndpointPath) &&
                            !context.Request.Path.StartsWithSegments(AlivenessEndpointPath);
                    })
                    .AddHttpClientInstrumentation();

                // EF Core instrumentation (package added). Verbosity via config.
                tracing.AddEntityFrameworkCoreInstrumentation(options =>
                {
                    // Always helpful to see which context
                    options.SetDbStatementForText = efVerbosity.Equals("All", StringComparison.OrdinalIgnoreCase) || efVerbosity.Equals("Commands", StringComparison.OrdinalIgnoreCase);
                    options.SetDbStatementForStoredProcedure = efVerbosity.Equals("All", StringComparison.OrdinalIgnoreCase) || efVerbosity.Equals("Commands", StringComparison.OrdinalIgnoreCase);
                    // Conditional enabling of sensitive data (ONLY for dev) controlled separately
                });

                // Optional: Sampling (100%) if configured
                var sampling = builder.Configuration["Telemetry:Tracing:Sampler"];
                if (string.Equals(sampling, "AlwaysOn", StringComparison.OrdinalIgnoreCase))
                {
                    tracing.SetSampler(new AlwaysOnSampler());
                }
                else if (string.Equals(sampling, "AlwaysOff", StringComparison.OrdinalIgnoreCase))
                {
                    tracing.SetSampler(new AlwaysOffSampler());
                }
            });

        builder.AddOpenTelemetryExporters();

        return builder;
    }

    private static TBuilder AddOpenTelemetryExporters<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        var endpoint = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]; // e.g. http://localhost:4317
        if (!string.IsNullOrWhiteSpace(endpoint))
        {
            // Attach OTLP exporter for traces & metrics (and logs already via Logging provider)
            builder.Services.AddOpenTelemetry()
                .UseOtlpExporter();
        }

        return builder;
    }

    public static TBuilder ConfigureSerilog<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        // Clear default providers so Serilog is the single source (OpenTelemetry provider added separately)
        builder.Logging.ClearProviders();

        Serilog.Debugging.SelfLog.Enable(Console.Error);

        var keyFilePath = builder.Configuration["environmentVariables:GOOGLE_APPLICATION_CREDENTIALS"];
        if (!string.IsNullOrEmpty(keyFilePath))
        {
            Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", keyFilePath);
        }
        var googleCloudProject = builder.Configuration["environmentVariables:GOOGLE_CLOUD_PROJECT"];
        if (!string.IsNullOrEmpty(googleCloudProject))
        {
            Environment.SetEnvironmentVariable("GOOGLE_CLOUD_PROJECT", googleCloudProject);
        }

        var projectId = googleCloudProject ?? builder.Configuration["Google:ProjectId"];

        var loggerConfiguration = new LoggerConfiguration()
            .ReadFrom.Configuration(builder.Configuration)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", builder.Environment.ApplicationName)
            .MinimumLevel.Override("Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware", LogEventLevel.Error)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .WriteTo.Console();

        string loggingMessage = "Serilog logging configured to write to Console";

        projectId = Environment.GetEnvironmentVariable("GOOGLE_CLOUD_PROJECT");
        keyFilePath = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");

        if (!string.IsNullOrWhiteSpace(projectId) && !string.IsNullOrWhiteSpace(keyFilePath))
        {
            loggerConfiguration.WriteTo.GoogleCloudLogging(projectId: projectId, logName: "MrWho");
            loggingMessage += $" and Google Cloud Logging (project: {projectId})";
        }

        var logger = loggerConfiguration.CreateLogger();
        Log.Logger = logger; // For static Log usage

        logger.Information(loggingMessage);

        builder.Logging.AddSerilog(logger, dispose: true);

        return builder;
    }

    public static TBuilder AddDefaultHealthChecks<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        builder.Services.AddHealthChecks()
            // Add a default liveness check to ensure app is responsive
            .AddCheck("self", () => HealthCheckResult.Healthy(), ["live"]);

        return builder;
    }

    public static WebApplication MapDefaultEndpoints(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.MapHealthChecks(HealthEndpointPath);
            app.MapHealthChecks(AlivenessEndpointPath, new HealthCheckOptions
            {
                Predicate = r => r.Tags.Contains("live")
            });
        }

        return app;
    }
}
