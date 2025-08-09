using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using MrWho.Data;
using System.IO;

namespace MrWho.Migrations.PostgreSql.Design;

public class PostgreSqlDesignTimeFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
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
        if (string.IsNullOrWhiteSpace(cs) || cs.Contains("MSSQL", StringComparison.OrdinalIgnoreCase) || cs.Contains("Trusted_Connection", StringComparison.OrdinalIgnoreCase) || cs.Contains("User Id=sa", StringComparison.OrdinalIgnoreCase))
        {
            cs = "Host=localhost;Database=MrWho;Username=postgres;Password=ChangeMe123!";
        }

        optionsBuilder.UseNpgsql(cs, b =>
        {
            b.MigrationsAssembly(typeof(PostgreSqlDesignTimeFactory).Assembly.FullName);
        });

        optionsBuilder.UseOpenIddict();
        return new ApplicationDbContext(optionsBuilder.Options);
    }
}
