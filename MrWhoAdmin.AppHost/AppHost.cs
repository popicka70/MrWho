using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using System.IO;

var builder = DistributedApplication.CreateBuilder(args);

// Detect test environment via custom env var or environment name
var isTesting = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase)
                || string.Equals(builder.Environment.EnvironmentName, "Testing", StringComparison.OrdinalIgnoreCase);

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


builder.Build().Run();
