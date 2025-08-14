using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

var builder = DistributedApplication.CreateBuilder(args);

// Read desired database provider from configuration/environment
var provider = builder.Configuration["Database:Provider"]
              ?? Environment.GetEnvironmentVariable("Database__Provider")
              ?? "SqlServer"; // default

// Create database resource conditionally
IResourceBuilder<IResourceWithConnectionString> database;
string migrationsAssembly;

switch (provider.ToLowerInvariant())
{
    case "postgres":
    case "postgresql":
        var pg = builder.AddPostgres("postgres")
            .WithDataVolume()
            .WithLifetime(ContainerLifetime.Persistent);
        database = pg.AddDatabase("mrwhodb");
        migrationsAssembly = "MrWho.Migrations.PostgreSql";
        provider = "PostgreSql";
        break;

    case "mysql":
    case "mariadb":
        var mysql = builder.AddMySql("mysql")
            .WithDataVolume()
            .WithLifetime(ContainerLifetime.Persistent);
        database = mysql.AddDatabase("mrwhodb");
        migrationsAssembly = "MrWho.Migrations.MySql";
        provider = "MySql";
        break;

    case "sqlserver":
    default:
        var sqlServer = builder.AddSqlServer("sqlserver")
            .WithDataVolume()
            .WithLifetime(ContainerLifetime.Persistent);
        database = sqlServer.AddDatabase("mrwhodb");
        migrationsAssembly = "MrWho.Migrations.SqlServer";
        provider = "SqlServer"; // normalize
        break;
}

var mrWho = builder.AddProject<Projects.MrWho>("mrwho")
    .WithReference(database)
    .WithEnvironment("Database__Provider", provider)
    .WithEnvironment("Database__MigrationsAssembly", migrationsAssembly)
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

builder.Build().Run();
