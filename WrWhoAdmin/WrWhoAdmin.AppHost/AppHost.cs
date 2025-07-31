var builder = DistributedApplication.CreateBuilder(args);

var apiService = builder.AddProject<Projects.WrWhoAdmin_ApiService>("apiservice")
    .WithHttpHealthCheck("/health");

builder.AddProject<Projects.WrWhoAdmin_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(apiService)
    .WaitFor(apiService);

builder.AddProject<Projects.MrWho>("mrwho");

builder.Build().Run();
