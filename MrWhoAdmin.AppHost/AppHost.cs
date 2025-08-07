var builder = DistributedApplication.CreateBuilder(args);

// Add SQL Server database
var sqlServer = builder.AddSqlServer("sqlserver")
    .WithDataVolume()
    .WithLifetime(ContainerLifetime.Persistent)
    .AddDatabase("mrwhodb");

var mrWho = builder.AddProject<Projects.MrWho>("mrwho")
    .WithReference(sqlServer)
    .WaitFor(sqlServer);

var adminWeb = builder.AddProject<Projects.MrWhoAdmin_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(mrWho)
    .WaitFor(mrWho);

builder.Build().Run();
