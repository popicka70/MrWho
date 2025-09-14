using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MrWho.Extensions;

namespace MrWho.Testing;

/// <summary>
/// Sample configuration helpers for test projects
/// </summary>
public static class TestConfiguration
{
    /// <summary>
    /// Example: Configure services for integration tests with shared database
    /// Use this pattern in your test WebApplicationFactory or test startup
    /// </summary>
    public static void ConfigureTestServices(IServiceCollection services)
    {
        // Option 1: Use shared test database (faster, but requires careful test design)
        services.AddSharedTestDatabase();

        // Option 2: Use isolated test database (slower, but each test is completely isolated)
        // services.AddIsolatedTestDatabase();

        // Option 3: Custom configuration
        // services.AddTestDatabaseConfiguration(options =>
        // {
        //     options.ForceUseEnsureCreated = true;
        //     options.SkipMigrations = true;
        //     options.RecreateDatabase = true;
        // });
    }

    /// <summary>
    /// Example: Configure services for development debugging with EnsureCreated
    /// Use this when you want to temporarily bypass migrations during development
    /// </summary>
    public static void ConfigureDevelopmentWithEnsureCreated(IServiceCollection services)
    {
        services.ForceEnsureCreatedInDevelopment();
    }

    /// <summary>
    /// Example: Setup method for individual test methods that need clean database state
    /// </summary>
    public static async Task SetupCleanDatabaseAsync(IServiceProvider serviceProvider)
    {
        await serviceProvider.RecreateTestDatabaseAsync();
    }

    /// <summary>
    /// Example: Cleanup method for individual test methods
    /// </summary>
    public static async Task CleanupTestDataAsync(IServiceProvider serviceProvider)
    {
        await serviceProvider.ClearTestDatabaseDataAsync();
    }
}

/// <summary>
/// Example WebApplicationFactory for integration tests
/// </summary>
/*
public class TestWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram> where TProgram : class
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Configure test-specific database behavior
            TestConfiguration.ConfigureTestServices(services);
            
            // You can also override other services here for testing
        });
        
        builder.UseEnvironment("Testing"); // Optional: set specific test environment
    }
}
*/
