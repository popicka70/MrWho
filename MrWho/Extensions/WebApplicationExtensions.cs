using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Services;
using OpenIddict.Abstractions;
using System.Linq;
using System.Reflection;

namespace MrWho.Extensions;

public static class WebApplicationExtensions
{
    public static async Task<WebApplication> ConfigureMrWhoPipelineAsync(this WebApplication app)
    {
        app.MapDefaultEndpoints();

        // Configure the HTTP request pipeline
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();

        // Add antiforgery middleware
        app.UseAntiforgery();

        app.UseAuthentication();
        app.UseAuthorization();

        // Initialize database and seed essential data
        await app.InitializeDatabaseAsync();

        // Configure routing for controllers
        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        return app;
    }

    public static WebApplication AddMrWhoEndpoints(this WebApplication app)
    {
        // OIDC Token endpoint - now uses injected TokenHandler
        app.MapPost("/connect/token", async (HttpContext context, ITokenHandler tokenHandler) =>
        {
            return await tokenHandler.HandleTokenRequestAsync(context);
        });

        // UserInfo endpoint (optional but recommended) - Updated to use OpenIddict validation
        app.MapGet("/connect/userinfo", async (HttpContext context, IUserInfoHandler userInfoHandler) =>
        {
            return await userInfoHandler.HandleUserInfoRequestAsync(context);
        }).RequireAuthorization();

        // API Test endpoint (for debugging) - This will now work with OpenIddict validation
        app.MapGet("/api/test", [Authorize] () =>
        {
            return Results.Ok(new { Message = "API is working!", Timestamp = DateTime.UtcNow });
        });

        return app;
    }

    public static WebApplication AddMrWhoDebugEndpoints(this WebApplication app)
    {
        // Token Inspector endpoint - redirect to controller
        app.MapGet("/identity/token-inspector", () => Results.Redirect("/identity/tokeninspector"));

        // Debug endpoints discovery
        app.MapGet("/debug", () => Results.Ok(new
        {
            Title = "MrWho Identity Server Debug Endpoints",
            Endpoints = new
            {
                TokenInspector = "/identity/token-inspector",
                ClientInfo = "/debug/client-info", 
                AdminClientInfo = "/debug/admin-client-info",
                EssentialData = "/debug/essential-data",
                ClientPermissions = "/debug/client-permissions",
                OpenIddictScopes = "/debug/openiddict-scopes"
            },
            Documentation = "Visit any endpoint above for debug information or tools"
        }));

        app.MapGet("/debug/client-info", async (IOidcClientService oidcClientService) =>
        {
            var clients = await oidcClientService.GetEnabledClientsAsync();
            var postmanClient = clients.FirstOrDefault(c => c.ClientId == "postman_client");
            
            if (postmanClient == null)
            {
                return Results.NotFound("Postman client not found");
            }
            
            return Results.Ok(new
            {
                ClientId = postmanClient.ClientId,
                ClientSecret = postmanClient.ClientSecret,
                AuthorizeUrl = "https://localhost:7000/connect/authorize",
                TokenUrl = "https://localhost:7000/connect/token",
                LogoutUrl = "https://localhost:7000/connect/logout",
                RedirectUris = postmanClient.RedirectUris.Select(ru => ru.Uri).ToArray(),
                PostLogoutRedirectUris = postmanClient.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
                SampleAuthUrl = $"https://localhost:7000/connect/authorize?client_id={postmanClient.ClientId}&response_type=code&redirect_uri=https://localhost:7002/signin-oidc&scope=openid%20email%20profile&state=test_state",
                SampleLogoutUrl = "https://localhost:7000/connect/logout?post_logout_redirect_uri=https://localhost:7002/signout-callback-oidc"
            });
        });

        // Debug endpoint to show actual database client configuration
        app.MapGet("/debug/db-client-config", async (IOpenIddictApplicationManager applicationManager, IOidcClientService oidcClientService) =>
        {
            var clients = await oidcClientService.GetEnabledClientsAsync();
            var clientConfigs = new List<object>();
            
            foreach (var client in clients)
            {
                var openIddictClient = await applicationManager.FindByClientIdAsync(client.ClientId);
                if (openIddictClient != null)
                {
                    clientConfigs.Add(new
                    {
                        ClientId = await applicationManager.GetClientIdAsync(openIddictClient),
                        DisplayName = await applicationManager.GetDisplayNameAsync(openIddictClient),
                        RedirectUris = await applicationManager.GetRedirectUrisAsync(openIddictClient),
                        PostLogoutRedirectUris = await applicationManager.GetPostLogoutRedirectUrisAsync(openIddictClient),
                        DatabaseConfiguration = new
                        {
                            client.ClientId,
                            client.Name,
                            client.IsEnabled,
                            RealmName = client.Realm.Name,
                            client.AllowAuthorizationCodeFlow,
                            client.AllowClientCredentialsFlow,
                            client.AllowPasswordFlow,
                            client.AllowRefreshTokenFlow
                        }
                    });
                }
            }
            
            return Results.Ok(clientConfigs);
        });

        app.MapGet("/debug/admin-client-info", async (IOidcClientService oidcClientService) =>
        {
            var clients = await oidcClientService.GetEnabledClientsAsync();
            var adminClient = clients.FirstOrDefault(c => c.ClientId == "mrwho_admin_web");
            
            if (adminClient == null)
            {
                return Results.NotFound("Admin client not found");
            }
            
            return Results.Ok(new
            {
                ClientId = adminClient.ClientId,
                ClientSecret = adminClient.ClientSecret,
                Name = adminClient.Name,
                RealmName = adminClient.Realm.Name,
                IsEnabled = adminClient.IsEnabled,
                AuthorizeUrl = "https://localhost:7113/connect/authorize",
                TokenUrl = "https://localhost:7113/connect/token",
                LogoutUrl = "https://localhost:7113/connect/logout",
                RedirectUris = adminClient.RedirectUris.Select(ru => ru.Uri).ToArray(),
                PostLogoutRedirectUris = adminClient.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
                Scopes = adminClient.Scopes.Select(s => s.Scope).ToArray(),
                SampleAuthUrl = $"https://localhost:7113/connect/authorize?client_id={adminClient.ClientId}&response_type=code&redirect_uri=https://localhost:7257/signin-oidc&scope=openid%20email%20profile%20roles%20api.read%20api.write&state=admin_test",
                SampleLogoutUrl = "https://localhost:7113/connect/logout?post_logout_redirect_uri=https://localhost:7257/signout-callback-oidc",
                AdminCredentials = new
                {
                    Username = "admin@mrwho.local",
                    Password = "MrWhoAdmin2024!"
                }
            });
        });

        // Debug endpoint for all essential data
        app.MapGet("/debug/essential-data", async (IOidcClientService oidcClientService, ApplicationDbContext context) =>
        {
            var adminRealm = await context.Realms.FirstOrDefaultAsync(r => r.Name == "admin");
            var adminClient = await context.Clients
                .Include(c => c.RedirectUris)
                .Include(c => c.PostLogoutUris)
                .Include(c => c.Scopes)
                .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web");
            var adminUser = await context.Users.FirstOrDefaultAsync(u => u.UserName == "admin@mrwho.local");
            
            return Results.Ok(new
            {
                AdminRealm = adminRealm != null ? new
                {
                    adminRealm.Id,
                    adminRealm.Name,
                    adminRealm.DisplayName,
                    adminRealm.Description,
                    adminRealm.IsEnabled
                } : null,
                AdminClient = adminClient != null ? new
                {
                    adminClient.Id,
                    adminClient.ClientId,
                    adminClient.Name,
                    adminClient.IsEnabled,
                    adminClient.RealmId,
                    RedirectUris = adminClient.RedirectUris.Select(ru => ru.Uri).ToArray(),
                    PostLogoutUris = adminClient.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
                    Scopes = adminClient.Scopes.Select(s => s.Scope).ToArray()
                } : null,
                AdminUser = adminUser != null ? new
                {
                    adminUser.Id,
                    adminUser.UserName,
                    adminUser.Email,
                    adminUser.EmailConfirmed
                } : null,
                SetupInstructions = new
                {
                    LoginUrl = "https://localhost:7257/login",
                    AdminCredentials = new
                    {
                        Username = "admin@mrwho.local",
                        Password = "MrWhoAdmin2024!"
                    }
                }
            });
        });

        // Debug endpoint to check the current client permissions and scopes in the database
        app.MapGet("/debug/client-permissions", async (IOidcClientService oidcClientService, ApplicationDbContext context) =>
        {
            var adminClient = await context.Clients
                .Include(c => c.Scopes)
                .Include(c => c.Permissions)
                .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web");
            
            if (adminClient == null)
            {
                return Results.NotFound("Admin client not found");
            }
            
            return Results.Ok(new
            {
                ClientId = adminClient.ClientId,
                Scopes = adminClient.Scopes.Select(s => s.Scope).ToArray(),
                Permissions = adminClient.Permissions.Select(p => p.Permission).ToArray(),
                ScopesWithApiAccess = adminClient.Scopes.Where(s => s.Scope.StartsWith("api.")).ToArray(),
                PermissionsWithApiAccess = adminClient.Permissions.Where(p => p.Permission.StartsWith("api.") || p.Permission.Contains("api.")).ToArray()
            });
        });

        // Debug endpoint to reset admin client (DEVELOPMENT ONLY)
        app.MapPost("/debug/reset-admin-client", async (ApplicationDbContext context, IOidcClientService oidcClientService, ILogger<Program> logger) =>
        {
            if (!app.Environment.IsDevelopment())
            {
                return Results.BadRequest("This endpoint is only available in development");
            }
            
            logger.LogWarning("RESETTING ADMIN CLIENT - This will delete and recreate the admin client");
            logger.LogWarning("Ensure you have a backup of your database before proceeding!");
            // Find and delete existing admin client
            var existingClient = await context.Clients
                .Include(c => c.RedirectUris)
                .Include(c => c.PostLogoutUris)
                .Include(c => c.Scopes)
                .Include(c => c.Permissions)
                .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web");
            
            if (existingClient != null)
            {
                context.Clients.Remove(existingClient);
                await context.SaveChangesAsync();
                logger.LogInformation("Deleted existing admin client");
            }
            
            // Recreate the client with correct permissions
            try 
            {
                await oidcClientService.InitializeEssentialDataAsync();
                return Results.Ok(new { message = "Admin client reset successfully", timestamp = DateTime.UtcNow });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error recreating admin client");
                return Results.Problem($"Error recreating admin client: {ex.Message}");
            }
        });

        // Debug endpoint to fix API permissions format (DEVELOPMENT ONLY)
        app.MapPost("/debug/fix-api-permissions", async (ApplicationDbContext context, IOidcClientService oidcClientService, ILogger<Program> logger) =>
        {
            if (!app.Environment.IsDevelopment())
            {
                return Results.BadRequest("This endpoint is only available in development");
            }
            
            logger.LogInformation("FIXING API PERMISSIONS - Updating permission format for all clients with API scopes");
            
            // Get all clients that have API scopes
            var clientsWithApiScopes = await context.Clients
                .Include(c => c.Scopes)
                .Include(c => c.Permissions)
                .Where(c => c.Scopes.Any(s => s.Scope.StartsWith("api.")))
                .ToListAsync();
            
            var updatedClients = new List<string>();
            
            foreach (var client in clientsWithApiScopes)
            {
                var hasChanges = false;
                
                // Remove old format permissions
                var oldPermissions = client.Permissions
                    .Where(p => p.Permission.StartsWith("oidc:scope:api.") || 
                               (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")))
                    .ToList();
                
                if (oldPermissions.Any())
                {
                    logger.LogInformation("Removing old API permissions for client {ClientId}: {Permissions}", 
                        client.ClientId, string.Join(", ", oldPermissions.Select(p => p.Permission)));
                    
                    foreach (var oldPerm in oldPermissions)
                    {
                        context.ClientPermissions.Remove(oldPerm);
                    }
                    hasChanges = true;
                }
                
                // Add correct format permissions
                var apiScopes = client.Scopes.Where(s => s.Scope.StartsWith("api.")).Select(s => s.Scope).ToList();
                foreach (var apiScope in apiScopes)
                {
                    var correctPermission = $"scp:{apiScope}";
                    if (!client.Permissions.Any(p => p.Permission == correctPermission))
                    {
                        logger.LogInformation("Adding correct API permission for client {ClientId}: {Permission}", 
                            client.ClientId, correctPermission);
                        
                        context.ClientPermissions.Add(new Models.ClientPermission
                        {
                            ClientId = client.Id,
                            Permission = correctPermission
                        });
                        hasChanges = true;
                    }
                }
                
                if (hasChanges)
                {
                    updatedClients.Add(client.ClientId);
                    
                    // Re-sync the client with OpenIddict
                    try
                    {
                        await oidcClientService.SyncClientWithOpenIddictAsync(client);
                        logger.LogInformation("Re-synced client {ClientId} with OpenIddict", client.ClientId);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Failed to re-sync client {ClientId} with OpenIddict", client.ClientId);
                    }
                }
            }
            
            if (updatedClients.Any())
            {
                await context.SaveChangesAsync();
                logger.LogInformation("Updated API permissions for clients: {Clients}", string.Join(", ", updatedClients));
                
                return Results.Ok(new 
                { 
                    message = "API permissions fixed successfully", 
                    updatedClients = updatedClients,
                    timestamp = DateTime.UtcNow 
                });
            }
            else
            {
                return Results.Ok(new 
                { 
                    message = "No API permission fixes needed", 
                    timestamp = DateTime.UtcNow 
                });
            }
        });

        // Debug endpoint to show OpenIddict scope information (DEVELOPMENT ONLY)
        app.MapGet("/debug/openiddict-scopes", async (IOpenIddictScopeManager scopeManager, ApplicationDbContext context) =>
        {
            var openIddictScopes = new List<object>();
            var databaseScopes = await context.Scopes
                .Where(s => s.IsEnabled)
                .OrderBy(s => s.Name)
                .ToListAsync();

            foreach (var dbScope in databaseScopes)
            {
                var openIddictScope = await scopeManager.FindByNameAsync(dbScope.Name);
                openIddictScopes.Add(new
                {
                    ScopeName = dbScope.Name,
                    DatabaseScope = new
                    {
                        dbScope.Id,
                        dbScope.Name,
                        dbScope.DisplayName,
                        dbScope.Description,
                        dbScope.IsEnabled,
                        dbScope.IsStandard,
                        dbScope.Type
                    },
                    OpenIddictScope = openIddictScope != null ? new
                    {
                        Id = await scopeManager.GetIdAsync(openIddictScope),
                        Name = await scopeManager.GetNameAsync(openIddictScope),
                        DisplayName = await scopeManager.GetDisplayNameAsync(openIddictScope),
                        Description = await scopeManager.GetDescriptionAsync(openIddictScope),
                        Resources = await scopeManager.GetResourcesAsync(openIddictScope)
                    } : null,
                    IsSynchronized = openIddictScope != null
                });
            }

            return Results.Ok(new
            {
                TotalDatabaseScopes = databaseScopes.Count,
                EnabledDatabaseScopes = databaseScopes.Count(s => s.IsEnabled),
                SynchronizedScopes = openIddictScopes.Count(s => ((dynamic)s).IsSynchronized),
                Scopes = openIddictScopes,
                Timestamp = DateTime.UtcNow
            });
        });

        // Debug endpoint to manually synchronize all scopes (DEVELOPMENT ONLY)
        app.MapPost("/debug/sync-scopes", async (IOpenIddictScopeSyncService scopeSyncService, ILogger<Program> logger) =>
        {
            if (!app.Environment.IsDevelopment())
            {
                return Results.BadRequest("This endpoint is only available in development");
            }
            
            try
            {
                await scopeSyncService.SynchronizeAllScopesAsync();
                return Results.Ok(new 
                { 
                    message = "All scopes synchronized with OpenIddict successfully", 
                    timestamp = DateTime.UtcNow 
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to synchronize scopes with OpenIddict");
                return Results.Problem($"Failed to synchronize scopes: {ex.Message}");
            }
        });
 
        return app;
    }

    private static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();
        var scopeSeederService = scope.ServiceProvider.GetRequiredService<IScopeSeederService>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        
        // Check for explicit database configuration options
        var dbOptions = scope.ServiceProvider.GetService<IOptions<DatabaseInitializationOptions>>()?.Value ?? new DatabaseInitializationOptions();
        
        // Detect if we're running in a test environment
        bool isTestEnvironment = IsTestEnvironment();
        
        // Determine database initialization strategy
        bool shouldUseEnsureCreated = isTestEnvironment || dbOptions.ForceUseEnsureCreated;
        bool shouldSkipMigrations = dbOptions.SkipMigrations;
        bool shouldRecreateDatabase = dbOptions.RecreateDatabase;

        if (shouldUseEnsureCreated)
        {
            // For tests or when explicitly configured: Use EnsureCreated for fast setup
            logger.LogInformation("Using EnsureCreated strategy for database setup (TestEnv: {IsTest}, Forced: {Forced})", 
                isTestEnvironment, dbOptions.ForceUseEnsureCreated);
            
            if (shouldRecreateDatabase)
            {
                logger.LogInformation("Recreating database for clean test state");
                await context.Database.EnsureDeletedAsync();
            }
            
            await context.Database.EnsureCreatedAsync();
            Console.WriteLine("Database created using EnsureCreated strategy");
        }
        else if (app.Environment.IsDevelopment())
        {
            // For development: Use migrations
            logger.LogInformation("Development environment - using migrations for database setup");
            
            if (!shouldSkipMigrations)
            {
                // Check if database exists, if not create it with migrations
                var pendingMigrations = await context.Database.GetPendingMigrationsAsync();
                if (pendingMigrations.Any())
                {
                    logger.LogInformation("Applying {Count} pending migrations: {Migrations}", 
                        pendingMigrations.Count(), string.Join(", ", pendingMigrations));
                    await context.Database.MigrateAsync();
                    Console.WriteLine($"Applied {pendingMigrations.Count()} pending migrations");
                }
                else
                {
                    logger.LogInformation("Database is up to date");
                    Console.WriteLine("Database is up to date - no migrations needed");
                }
            }
            else
            {
                logger.LogInformation("Skipping migrations as requested by configuration");
            }
        }
        else
        {
            // For production: Use migrations
            logger.LogInformation("Production environment - using migrations for database setup");
            if (!shouldSkipMigrations)
            {
                await context.Database.MigrateAsync();
            }
        }
        
        // Initialize standard scopes first
        try
        {
            await scopeSeederService.InitializeStandardScopesAsync();
            Console.WriteLine("Standard scopes initialized successfully in database");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing standard scopes: {ex.Message}");
            throw;
        }
        
        // CRITICAL: Synchronize all scopes from database with OpenIddict
        try
        {
            var scopeSyncService = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeSyncService>();
            await scopeSyncService.SynchronizeAllScopesAsync();
            Console.WriteLine("All database scopes synchronized with OpenIddict successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error synchronizing scopes with OpenIddict: {ex.Message}");
            throw;
        }
        
        // Initialize essential data (admin realm, admin client, admin user)
        try
        {
            await oidcClientService.InitializeEssentialDataAsync();
            Console.WriteLine("Essential OIDC data initialized successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing essential OIDC data: {ex.Message}");
            throw;
        }
        
        // Seed additional test users for development
        if (!await context.Users.AnyAsync(u => u.UserName == "test@example.com"))
        {
            var testUser = new IdentityUser 
            { 
                UserName = "test@example.com", 
                Email = "test@example.com", 
                EmailConfirmed = true 
            };
            await userManager.CreateAsync(testUser, "Test123!");
            Console.WriteLine("Created test user");
        }
        
        // Initialize default realm and clients using the dynamic service (keeping for backwards compatibility)
        try
        {
            await oidcClientService.InitializeDefaultRealmAndClientsAsync();
            Console.WriteLine("Dynamic OIDC client configuration initialized successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing dynamic OIDC client configuration: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Detects if the application is running in a test environment
    /// </summary>
    private static bool IsTestEnvironment()
    {
        // Method 1: Check if any test framework assemblies are loaded
        var loadedAssemblies = AppDomain.CurrentDomain.GetAssemblies();
        var testAssemblies = new[]
        {
            "Microsoft.VisualStudio.TestTools.UnitTesting",
            "MSTest",
            "xunit",
            "nunit",
            "Aspire.Hosting.Testing"
        };

        bool hasTestAssemblies = loadedAssemblies.Any(assembly =>
            testAssemblies.Any(testAssembly => 
                assembly.FullName?.Contains(testAssembly, StringComparison.OrdinalIgnoreCase) == true));

        // Method 2: Check for environment variables commonly set in test environments
        bool hasTestEnvironmentVariables = 
            Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true" ||
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Testing" ||
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("VSTEST_HOST_DEBUG"));

        // Method 3: Check if the entry assembly is a test project (has test-related attributes)
        bool isTestProject = false;
        try
        {
            var entryAssembly = Assembly.GetEntryAssembly();
            if (entryAssembly != null)
            {
                // Check for common test project indicators
                var assemblyName = entryAssembly.GetName().Name;
                isTestProject = assemblyName?.Contains("Test", StringComparison.OrdinalIgnoreCase) == true ||
                               assemblyName?.Contains("MrWhoAdmin.Tests", StringComparison.OrdinalIgnoreCase) == true;
            }
        }
        catch
        {
            // Ignore errors when checking entry assembly
        }

        bool isTest = hasTestAssemblies || hasTestEnvironmentVariables || isTestProject;
        
        if (isTest)
        {
            Console.WriteLine($"Test environment detected: TestAssemblies={hasTestAssemblies}, TestEnvVars={hasTestEnvironmentVariables}, TestProject={isTestProject}");
        }
        
        return isTest;
    }
}