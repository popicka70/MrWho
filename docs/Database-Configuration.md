# Database Configuration Guide

## Overview

The MrWho project now uses a flexible database initialization strategy that automatically detects the environment and chooses the appropriate database setup method:

- **Development Environment**: Uses Entity Framework migrations
- **Production Environment**: Uses Entity Framework migrations  
- **Test Environment**: Uses `EnsureCreatedAsync()` for fast setup

## How It Works

### Automatic Environment Detection

The system automatically detects test environments using multiple indicators:

1. **Test Assembly Detection**: Looks for test framework assemblies like MSTest, xUnit, NUnit
2. **Environment Variables**: Checks for test-specific environment variables
3. **Project Name**: Detects if the entry assembly name contains "Test"

### Database Initialization Strategies

#### Development Environment
```csharp
// Uses migrations - keeps your database schema up to date
await context.Database.MigrateAsync();
```

#### Test Environment  
```csharp
// Uses EnsureCreatedAsync - fast database creation for tests
await context.Database.EnsureCreatedAsync();
```

## Configuration Options

### Basic Test Configuration

For most test scenarios, the automatic detection works perfectly. However, you can explicitly configure database behavior:

```csharp
// In your test project's service configuration
services.AddSharedTestDatabase(); // Fast setup, shared database
// OR
services.AddIsolatedTestDatabase(); // Each test gets fresh database
```

### Advanced Configuration

You can fine-tune the database initialization behavior:

```csharp
services.AddTestDatabaseConfiguration(options =>
{
    options.ForceUseEnsureCreated = true;  // Force EnsureCreated even in dev
    options.SkipMigrations = true;         // Skip migration checks
    options.RecreateDatabase = false;      // Don't recreate on each init
});
```

### Development Override

If you want to temporarily use EnsureCreated in development (useful for debugging):

```csharp
// In development Startup/Program.cs
if (builder.Environment.IsDevelopment())
{
    services.ForceEnsureCreatedInDevelopment();
}
```

## Test Project Setup Examples

### Option 1: Shared Test Infrastructure (Recommended)

```csharp
// In your test class or WebApplicationFactory
public class TestWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram> 
    where TProgram : class
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // This will automatically use EnsureCreatedAsync in tests
            services.AddSharedTestDatabase();
        });
    }
}
```

### Option 2: Isolated Test Database

```csharp
public class IsolatedTestWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram> 
    where TProgram : class
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Each test gets a fresh database (slower but more isolated)
            services.AddIsolatedTestDatabase();
        });
    }
}
```

### Option 3: Manual Database Management

```csharp
[TestMethod]
public async Task MyTest_WithCleanDatabase()
{
    // Setup - Create fresh database
    await serviceProvider.RecreateTestDatabaseAsync();
    
    try
    {
        // Your test logic here
        var result = await someService.DoSomething();
        
        // Assertions
        result.Should().NotBeNull();
    }
    finally
    {
        // Cleanup - Clear test data
        await serviceProvider.ClearTestDatabaseDataAsync();
    }
}
```

## Migration Workflows

### Development Workflow

1. **Make model changes** in your entity classes
2. **Create migration**: `dotnet ef migrations add YourMigrationName`
3. **Run application**: Migrations are applied automatically
4. **Commit migration files** to version control

### Production Deployment

1. **Build application** with all migrations included
2. **Deploy application**: Migrations are applied automatically on startup
3. **Zero downtime**: EF Core migrations are designed for production use

### Test Environment

1. **Run tests**: Database is created automatically using EnsureCreatedAsync
2. **No migration files needed**: Schema is generated from current model
3. **Fast execution**: No migration history to process

## Available Helper Methods

### Database Management

```csharp
// Manually create test database
await serviceProvider.EnsureTestDatabaseCreatedAsync();

// Recreate database (delete + create)
await serviceProvider.RecreateTestDatabaseAsync();

// Clear all data but keep schema
await serviceProvider.ClearTestDatabaseDataAsync();
```

### Service Configuration

```csharp
// Test-specific configurations
services.AddSharedTestDatabase();           // Shared DB for fast tests
services.AddIsolatedTestDatabase();         // Isolated DB per test
services.ForceEnsureCreatedInDevelopment(); // Override dev behavior
```

## Best Practices

### For Test Projects

1. **Use shared infrastructure** when possible for faster test execution
2. **Clean up test data** if tests modify shared database state  
3. **Use isolated databases** only when tests need complete isolation
4. **Avoid testing migrations** in unit/integration tests - test your business logic

### For Development

1. **Create migrations** for all schema changes
2. **Review migration files** before committing
3. **Test migrations** on staging environment before production
4. **Keep migrations focused** - one logical change per migration

### For Production

1. **Always use migrations** for schema changes
2. **Test migration rollback** procedures
3. **Monitor migration execution** during deployment
4. **Have rollback plan** for failed migrations

## Troubleshooting

### Tests Not Using EnsureCreated

Check if your test environment is properly detected:

```csharp
// Add this to see detection logic in action
Console.WriteLine($"Test environment detected: {IsTestEnvironment()}");
```

### Development Using Wrong Strategy

Verify your environment configuration:

```csharp
// Check what strategy is being used
logger.LogInformation("Using database strategy: {Strategy}", 
    isTestEnvironment ? "EnsureCreated" : "Migrations");
```

### Migration Issues

Common solutions:

```bash
# Reset migrations (development only)
dotnet ef database drop
dotnet ef migrations remove
dotnet ef migrations add InitialCreate

# Update database manually
dotnet ef database update
```

## File Structure

The database configuration is organized across these files:

- `MrWho/Extensions/WebApplicationExtensions.cs` - Main initialization logic
- `MrWho/Extensions/ServiceCollectionExtensions.cs` - Service registration
- `MrWho/Extensions/TestDatabaseExtensions.cs` - Test-specific helpers  
- `MrWho/Testing/TestConfiguration.cs` - Example configurations
- `MrWho/Migrations/` - EF Core migration files

This flexible approach ensures optimal performance in all environments while maintaining data integrity and developer productivity.