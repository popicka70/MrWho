using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

var builder = DistributedApplication.CreateBuilder(args);

// Aspire no longer provisions databases; we connect to an external persistent DB.

var mrWho = builder.AddProject<Projects.MrWho>("mrwho")
    .WithExternalHttpEndpoints();

var adminWeb = builder.AddProject<Projects.MrWhoAdmin_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho);

var demo1 = builder.AddProject<Projects.MrWhoDemo1>("mrwhodemo1")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho);

var demoNuget = builder.AddProject<Projects.MrWhoDemoNuget>("mrwhodemonuget")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho);

builder.Build().Run();
