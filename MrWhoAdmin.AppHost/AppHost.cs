using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using System.IO;

var builder = DistributedApplication.CreateBuilder(args);

// Aspire no longer provisions databases; we connect to an external persistent DB.

// Compute local full path to the GCP service account key for dev runs
// NOTE: Do NOT commit keys to source control. Prefer secrets outside the repo in production.
var credsRelative = Path.Combine("..", "MrWho", "etc", "secrets", "mrwho-1755324848344-21f187c4a986.json");
var credsFullPath = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), credsRelative));
var gcpProjectId = "mrwho-1755324848344";

var mrWho = builder.AddProject<Projects.MrWho>("mrwho")
    .WithExternalHttpEndpoints()
    .WithEnvironment("GOOGLE_APPLICATION_CREDENTIALS", credsFullPath)
    .WithEnvironment("GOOGLE_CLOUD_PROJECT", gcpProjectId);

var adminWeb = builder.AddProject<Projects.MrWhoAdmin_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho)
    .WithEnvironment("GOOGLE_APPLICATION_CREDENTIALS", credsFullPath)
    .WithEnvironment("GOOGLE_CLOUD_PROJECT", gcpProjectId);

var demo1 = builder.AddProject<Projects.MrWhoDemo1>("mrwhodemo1")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho)
    .WithEnvironment("GOOGLE_APPLICATION_CREDENTIALS", credsFullPath)
    .WithEnvironment("GOOGLE_CLOUD_PROJECT", gcpProjectId);

var demoNuget = builder.AddProject<Projects.MrWhoDemoNuget>("mrwhodemonuget")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho)
    .WithEnvironment("GOOGLE_APPLICATION_CREDENTIALS", credsFullPath)
    .WithEnvironment("GOOGLE_CLOUD_PROJECT", gcpProjectId);

builder.Build().Run();
