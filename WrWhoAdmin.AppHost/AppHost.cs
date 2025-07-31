var builder = DistributedApplication.CreateBuilder(args);

// Add SQL Server database
var sqlServer = builder.AddSqlServer("sqlserver")
    .WithDataVolume()
    .AddDatabase("mrwhodb");

var apiService = builder.AddProject<Projects.MrWhoAdmin_ApiService>("apiservice")
    .WithHttpHealthCheck("/health");

builder.AddProject<Projects.MrWhoAdmin_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(apiService)
    .WaitFor(apiService);

builder.AddProject<Projects.MrWho>("mrwho")
    .WithReference(sqlServer)
    .WaitFor(sqlServer);

builder.Build().Run();
