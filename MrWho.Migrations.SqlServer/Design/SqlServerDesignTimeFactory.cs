using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using MrWho.Data;
using System.IO;

namespace MrWho.Migrations.SqlServer.Design;

public class SqlServerDesignTimeFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        // Load configuration from the main project
        var config = new ConfigurationBuilder()
            .SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "..", "MrWho"))
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

        var cs = config.GetConnectionString("mrwhodb") ??
                 config["ConnectionStrings:mrwhodb"] ??
                 "Server=(localdb)\\MSSQLLocalDB;Database=MrWho;Trusted_Connection=True;MultipleActiveResultSets=True;TrustServerCertificate=True";

        optionsBuilder.UseSqlServer(cs, sql =>
        {
            sql.MigrationsAssembly(typeof(SqlServerDesignTimeFactory).Assembly.FullName);
        });

        optionsBuilder.UseOpenIddict();

        return new ApplicationDbContext(optionsBuilder.Options);
    }
}
