using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MrWho.Data;

namespace MrWho.Extensions;

/// <summary>
/// Extension methods specifically for configuring database behavior in test scenarios
/// </summary>
public static class TestDatabaseExtensions
{
    /// <summary>
    /// Configures the database for test scenarios with specific behavior
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Optional configuration for database initialization</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddTestDatabaseConfiguration(
        this IServiceCollection services,
        Action<DatabaseInitializationOptions>? configureOptions = null)
    {
        var options = new DatabaseInitializationOptions
        {
            ForceUseEnsureCreated = true,
            SkipMigrations = true,
            RecreateDatabase = false // Default to false for shared test infrastructure
        };

        configureOptions?.Invoke(options);

        return services.Configure<DatabaseInitializationOptions>(dbOptions =>
        {
            dbOptions.ForceUseEnsureCreated = options.ForceUseEnsureCreated;
            dbOptions.SkipMigrations = options.SkipMigrations;
            dbOptions.RecreateDatabase = options.RecreateDatabase;
        });
    }

    /// <summary>
    /// Configures database for isolated test scenarios where each test gets a fresh database
    /// </summary>
    public static IServiceCollection AddIsolatedTestDatabase(this IServiceCollection services)
    {
        return services.AddTestDatabaseConfiguration(options =>
        {
            options.ForceUseEnsureCreated = true;
            options.SkipMigrations = true;
            options.RecreateDatabase = true; // Each test gets fresh database
        });
    }

    /// <summary>
    /// Configures database for shared test scenarios where tests share the same database
    /// </summary>
    public static IServiceCollection AddSharedTestDatabase(this IServiceCollection services)
    {
        return services.AddTestDatabaseConfiguration(options =>
        {
            options.ForceUseEnsureCreated = true;
            options.SkipMigrations = true;
            options.RecreateDatabase = false; // Tests share the same database
        });
    }

    /// <summary>
    /// Forces the use of EnsureCreatedAsync for development scenarios (useful for debugging)
    /// </summary>
    public static IServiceCollection ForceEnsureCreatedInDevelopment(this IServiceCollection services)
    {
        return services.AddTestDatabaseConfiguration(options =>
        {
            options.ForceUseEnsureCreated = true;
            options.SkipMigrations = true;
            options.RecreateDatabase = false;
        });
    }

    /// <summary>
    /// Manually initializes the database using EnsureCreatedAsync (useful in test setup)
    /// </summary>
    public static async Task EnsureTestDatabaseCreatedAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();
    }

    /// <summary>
    /// Manually drops and recreates the database (useful in test cleanup)
    /// </summary>
    public static async Task RecreateTestDatabaseAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureDeletedAsync();
        await context.Database.EnsureCreatedAsync();
    }

    /// <summary>
    /// Clears all data from the database while keeping the schema (useful for test cleanup)
    /// </summary>
    public static async Task ClearTestDatabaseDataAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        // Clear all custom entities first (due to foreign key constraints)
        context.ClientPermissions.RemoveRange(context.ClientPermissions);
        context.ClientScopes.RemoveRange(context.ClientScopes);
        context.ClientPostLogoutUris.RemoveRange(context.ClientPostLogoutUris);
        context.ClientRedirectUris.RemoveRange(context.ClientRedirectUris);
        context.Clients.RemoveRange(context.Clients);
        context.ScopeClaims.RemoveRange(context.ScopeClaims);
        context.Scopes.RemoveRange(context.Scopes);
        context.Realms.RemoveRange(context.Realms);

        // Clear Identity entities
        context.UserRoles.RemoveRange(context.UserRoles);
        context.UserClaims.RemoveRange(context.UserClaims);
        context.UserLogins.RemoveRange(context.UserLogins);
        context.UserTokens.RemoveRange(context.UserTokens);
        context.RoleClaims.RemoveRange(context.RoleClaims);
        context.Users.RemoveRange(context.Users);
        context.Roles.RemoveRange(context.Roles);

        await context.SaveChangesAsync();
    }
}