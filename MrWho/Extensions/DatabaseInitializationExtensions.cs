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

            // Use EF Core migrations in normal environments
            await db.Database.MigrateAsync();

            // Seed essential data (realms, clients, users)
            var seed = services.GetRequiredService<IOidcClientService>();
            await seed.InitializeEssentialDataAsync();
            await seed.InitializeDefaultRealmAndClientsAsync();

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
                throw; // rethrow so startup fails clearly if schemes missing
            }

            logger.LogInformation("Database initialized successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during database initialization");
            throw;
        }
    }
}
