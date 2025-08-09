using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using MrWho.Data;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using System.IO;

namespace MrWho.Migrations.MySql.Design;

public class MySqlDesignTimeFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "..", "MrWho"))
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

        var cs = config.GetConnectionString("mrwhodb") ?? config["ConnectionStrings:mrwhodb"];
        // If the found connection string looks like a SQL Server string, ignore it for MySQL migrations
        if (string.IsNullOrWhiteSpace(cs) || cs.Contains("MSSQL", StringComparison.OrdinalIgnoreCase) || cs.Contains("Trusted_Connection", StringComparison.OrdinalIgnoreCase) || cs.Contains("User Id=sa", StringComparison.OrdinalIgnoreCase))
        {
            cs = "Server=localhost;Database=MrWho;User ID=root;Password=ChangeMe123!;";
        }

        // Try flavor/version from config, fallback to sane defaults
        var flavor = (config["Database:MySql:Flavor"] ?? "MySql").Trim();
        var versionText = config["Database:MySql:Version"] ?? (flavor.Equals("MariaDb", StringComparison.OrdinalIgnoreCase) ? "11.2.0" : "8.0.36");
        Version.TryParse(versionText, out var parsed);
        parsed ??= new Version(8,0,36);

        if (flavor.Equals("MariaDb", StringComparison.OrdinalIgnoreCase))
        {
            optionsBuilder.UseMySql(cs, new MariaDbServerVersion(parsed), b =>
            {
                b.MigrationsAssembly(typeof(MySqlDesignTimeFactory).Assembly.FullName);
            });
        }
        else
        {
            optionsBuilder.UseMySql(cs, new MySqlServerVersion(parsed), b =>
            {
                b.MigrationsAssembly(typeof(MySqlDesignTimeFactory).Assembly.FullName);
            });
        }

        optionsBuilder.UseOpenIddict();
        return new ApplicationDbContext(optionsBuilder.Options);
    }
}
