using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Services;

namespace MrWho.Extensions;

public static class DatabaseInitializationExtensions
{
    public static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;

        var env = services.GetRequiredService<IHostEnvironment>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("DbInit");

        try
        {
            var db = services.GetRequiredService<ApplicationDbContext>();

            // Apply EF Core migrations (dev/prod). Tests may override elsewhere.
            await db.Database.MigrateAsync();

            // Consolidated seeding: single service performs ALL essential seeding idempotently
            var seeder = services.GetRequiredService<ISeedingService>();
            await seeder.SeedAsync();

            // AFTER seeding, register all dynamic client/realm cookie schemes (idempotent)
            try
            {
                var registrar = services.GetRequiredService<IDynamicClientCookieRegistrar>();
                await registrar.RegisterAllAsync();
                logger.LogInformation("Dynamic client cookie schemes registered after seeding");
            }
            catch (Exception regEx)
            {
                logger.LogError(regEx, "Failed to register dynamic client cookie schemes after seeding");
                throw; // Fail fast so missing schemes are obvious
            }

            logger.LogInformation("Database initialized & seeded successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during database initialization");
            throw;
        }
    }
}
