using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Hosting; // for HostOptions
using Microsoft.Extensions.DependencyInjection; // for IServiceCollection.Configure
using System.IO;

var builder = DistributedApplication.CreateBuilder(args);

// Detect test environment via custom env var or environment name
var isTesting = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase)
                || string.Equals(builder.Environment.EnvironmentName, "Testing", StringComparison.OrdinalIgnoreCase);

// Increase graceful shutdown timeout to avoid TaskCanceled noise on shutdown in slower environments/tests
builder.Services.Configure<HostOptions>(options =>
{
    options.ShutdownTimeout = TimeSpan.FromSeconds(60);
});

var mrWho = builder.AddProject<Projects.MrWho>("mrwho")
    .WithExternalHttpEndpoints();

// Conditionally create ephemeral Postgres database ONLY for tests
if (isTesting)
{
    // Define password as a parameter resource (required by Aspire Postgres component)
    var pgPassword = builder.AddParameter("pgPassword", value: "MrWhoTests!123");

    // Create a postgres server + database named mrwhodb so connection string key matches application expectation: ConnectionStrings:mrwhodb
    var pg = builder.AddPostgres("postgres", password: pgPassword)
                    .WithLifetime(ContainerLifetime.Session); // stop when test session ends
    var mrWhoDb = pg.AddDatabase("mrwhodb");

    // Inject connection string into MrWho app during tests
    mrWho.WithReference(mrWhoDb);
}

var adminWeb = builder.AddProject<Projects.MrWhoAdmin_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho);

var demoApi = builder.AddProject<Projects.MrWhoDemoApi>("mrwhodemoapi");

var demo1 = builder.AddProject<Projects.MrWhoDemo1>("mrwhodemo1")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WithReference(demoApi)
    .WaitFor(mrWho)
    .WaitFor(demoApi);

var demoNuget = builder.AddProject<Projects.MrWhoDemoNuget>("mrwhodemonuget")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho);


var app = builder.Build();
try
{
    // Use async run and swallow cancellation to prevent AggregateException(TaskCanceled) on shutdown
    await app.RunAsync();
}
catch (TaskCanceledException)
{
    // Suppress in case some hosts surface TaskCanceled directly
}
catch (OperationCanceledException)
{
    // Expected during controlled shutdown (e.g., test harness cancellation). Suppress noisy exception.
}
