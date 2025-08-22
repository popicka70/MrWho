using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using System.IO;

var builder = DistributedApplication.CreateBuilder(args);

var mrWho = builder.AddProject<Projects.MrWho>("mrwho")
    .WithExternalHttpEndpoints();

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
