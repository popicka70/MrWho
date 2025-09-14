using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Services;
using Npgsql; // for NpgsqlException

namespace MrWho.Extensions;

public static class DatabaseInitializationExtensions
{
    public static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;

        var env = services.GetRequiredService<IHostEnvironment>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("DbInit");

        // Detect test mode (Aspire test host sets env var in SharedTestInfrastructure)
        var isTestMode = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(env.EnvironmentName, "Testing", StringComparison.OrdinalIgnoreCase);

        try
        {
            var db = services.GetRequiredService<ApplicationDbContext>();

            if (isTestMode)
            {
                logger.LogInformation("[DB INIT] Test mode detected -> using EnsureCreated with retry (skipping migrations)");
                await EnsureCreatedWithRetryAsync(db, logger, maxAttempts: 12, baseDelayMs: 500);
            }
            else
            {
                // Apply EF Core migrations (dev/prod)
                await db.Database.MigrateAsync();
            }

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

            logger.LogInformation("Database initialized & seeded successfully (Mode: {Mode})", isTestMode ? "Test" : env.EnvironmentName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during database initialization");
            throw;
        }
    }

    private static async Task EnsureCreatedWithRetryAsync(ApplicationDbContext db, ILogger logger, int maxAttempts, int baseDelayMs)
    {
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                // Explicitly open a raw connection first so we fail fast before EnsureCreated allocates resources
                var connection = db.Database.GetDbConnection();
                if (connection.State != System.Data.ConnectionState.Open)
                {
                    await connection.OpenAsync();
                }

                // Lightweight readiness probe
                if (connection is NpgsqlConnection npgsqlConn)
                {
                    using var cmd = npgsqlConn.CreateCommand();
                    cmd.CommandText = "SELECT 1";
                    await cmd.ExecuteScalarAsync();
                }

                // Now ensure schema
                await db.Database.EnsureCreatedAsync();
                logger.LogInformation("[DB INIT] EnsureCreated succeeded on attempt {Attempt}/{MaxAttempts}", attempt, maxAttempts);
                return;
            }
            catch (Exception ex) when (IsTransient(ex) && attempt < maxAttempts)
            {
                var delay = TimeSpan.FromMilliseconds(baseDelayMs * Math.Min(10, attempt));
                logger.LogWarning(ex, "[DB INIT] EnsureCreated transient failure attempt {Attempt}/{MaxAttempts}. Retrying in {Delay}...", attempt, maxAttempts, delay);
                await Task.Delay(delay);
            }
        }

        // One final attempt without catching to surface the real exception
        await db.Database.EnsureCreatedAsync();
    }

    private static bool IsTransient(Exception ex)
    {
        return ex switch
        {
            NpgsqlException => true,
            TimeoutException => true,
            EndOfStreamException => true,
            IOException => true,
            SocketException => true,
            _ when ex.Message.Contains("Connection refused", StringComparison.OrdinalIgnoreCase) => true,
            _ when ex.InnerException is not null && IsTransient(ex.InnerException) => true,
            _ => false
        };
    }
}
