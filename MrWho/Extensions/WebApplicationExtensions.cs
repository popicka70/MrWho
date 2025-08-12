using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Services;
using MrWho.Services.Mediator;
using MrWho.Endpoints;
using MrWho.Middleware;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using static OpenIddict.Abstractions.OpenIddictConstants;
using MrWho.Shared;
using Microsoft.AspNetCore.HttpOverrides;

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

    // Behind a reverse proxy (Railway, containers), honor X-Forwarded-* so Request.Scheme becomes https
    // Place this BEFORE redirection/auth so downstream sees the correct scheme/remote IP. Options are configured in DI.
    app.UseForwardedHeaders();

        // Allow disabling HTTPS redirection for containerized/internal HTTP calls
        var disableHttpsRedirect = string.Equals(Environment.GetEnvironmentVariable("DISABLE_HTTPS_REDIRECT"), "true", StringComparison.OrdinalIgnoreCase);
        if (!disableHttpsRedirect)
        {
            app.UseHttpsRedirection();
        }
        app.UseStaticFiles();
        app.UseRouting();

        // Add client cookie middleware before authentication
        app.UseMiddleware<ClientCookieMiddleware>();

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

        // CRITICAL: Map API controllers for token inspector and other API endpoints
        app.MapControllers();

        return app;
    }

    /// <summary>
    /// Configures the MrWho pipeline with client-specific cookie support
    /// </summary>
    public static async Task<WebApplication> ConfigureMrWhoPipelineWithClientCookiesAsync(this WebApplication app)
    {
        app.MapDefaultEndpoints();

        // Configure the HTTP request pipeline
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

    // Behind a reverse proxy (Railway, containers), honor X-Forwarded-* so Request.Scheme becomes https
    // Options are configured in DI; use parameterless overload here.
    app.UseForwardedHeaders();

        // Allow disabling HTTPS redirection for containerized/internal HTTP calls
        var disableHttpsRedirect = string.Equals(Environment.GetEnvironmentVariable("DISABLE_HTTPS_REDIRECT"), "true", StringComparison.OrdinalIgnoreCase);
        if (!disableHttpsRedirect)
        {
            app.UseHttpsRedirection();
        }
        app.UseStaticFiles();
        app.UseRouting();

        // Enable session support for client tracking
        app.UseSession();

        // Add client cookie middleware before authentication - CRITICAL for client-specific cookies
        app.UseMiddleware<ClientCookieMiddleware>();

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

        // CRITICAL: Map API controllers for token inspector and other API endpoints
        app.MapControllers();

        return app;
    }

    public static WebApplication AddMrWhoEndpoints(this WebApplication app)
    {
        // OIDC Authorization endpoint via mediator
        app.MapGet("/connect/authorize", async (HttpContext context, IMediator mediator) =>
        {
            return await mediator.Send(new OidcAuthorizeRequest(context));
        });

        app.MapPost("/connect/authorize", async (HttpContext context, IMediator mediator) =>
        {
            return await mediator.Send(new OidcAuthorizeRequest(context));
        });

        // Token endpoint via mediator
        app.MapPost("/connect/token", async (HttpContext context, IMediator mediator) =>
        {
            return await mediator.Send(new OidcTokenRequest(context));
        });

        // NOTE: Logout endpoint removed from minimal API to avoid conflict with AuthController
        // The AuthController.Logout method handles both GET and POST /connect/logout
        // This provides better UI integration and proper logout confirmation pages

        // UserInfo endpoint via mediator
        app.MapGet("/connect/userinfo", async (HttpContext context, IMediator mediator) =>
        {
            return await mediator.Send(new UserInfoRequest(context));
        }).RequireAuthorization("UserInfoPolicy");

        app.MapPost("/connect/userinfo", async (HttpContext context, IMediator mediator) =>
        {
            return await mediator.Send(new UserInfoRequest(context));
        }).RequireAuthorization("UserInfoPolicy");

        // REDIRECT: Handle legacy /Account/AccessDenied to correct route
        app.MapGet("/Account/AccessDenied", (HttpContext context) =>
        {
            var returnUrl = context.Request.Query["ReturnUrl"].ToString();
            var redirectUrl = "/connect/access-denied";
            if (!string.IsNullOrEmpty(returnUrl))
            {
                redirectUrl += $"?ReturnUrl={Uri.EscapeDataString(returnUrl)}";
            }
            return Results.Redirect(redirectUrl);
        });

        return app;
    }

    public static WebApplication AddMrWhoDebugEndpoints(this WebApplication app)
    {
        // Group all debug endpoints and secure with AdminClientApi policy
        var debug = app.MapGroup("/debug").RequireAuthorization(AuthorizationPolicies.AdminClientApi);

        // Debug endpoints discovery via mediator
        debug.MapGet("/", (IMediator mediator) => mediator.Send(new DebugIndexRequest()));

        // Client cookies
        debug.MapGet("/client-cookies", (HttpContext context, IMediator mediator) => mediator.Send(new ClientCookiesDebugRequest(context)));
        debug.MapGet("/client-info", (IMediator mediator) => mediator.Send(new ClientInfoRequest()));

        // DB client config
        debug.MapGet("/db-client-config", (IMediator mediator) => mediator.Send(new DbClientConfigRequest()));
        debug.MapGet("/admin-client-info", (IMediator mediator) => mediator.Send(new AdminClientInfoRequest()));
        debug.MapGet("/demo1-client-info", (IMediator mediator) => mediator.Send(new Demo1ClientInfoRequest()));

        // Essential data
        debug.MapGet("/essential-data", (IMediator mediator) => mediator.Send(new EssentialDataRequest()));

        // Client permissions
        debug.MapGet("/client-permissions", (IMediator mediator) => mediator.Send(new ClientPermissionsRequest()));

        // Dev-only endpoints
        debug.MapPost("/reset-admin-client", (IMediator mediator) => mediator.Send(new ResetAdminClientRequest()));
        debug.MapPost("/fix-api-permissions", (IMediator mediator) => mediator.Send(new FixApiPermissionsRequest()));
        debug.MapGet("/openiddict-scopes", (IMediator mediator) => mediator.Send(new OpenIddictScopesRequest()));
        debug.MapPost("/sync-scopes", (IMediator mediator) => mediator.Send(new SyncScopesRequest()));

        // User/claims related
        debug.MapGet("/userinfo-test", (HttpContext context, IMediator mediator) => mediator.Send(new UserInfoTestRequest(context)));
        debug.MapGet("/current-claims", (HttpContext context, IMediator mediator) => mediator.Send(new CurrentClaimsRequest(context)));
        debug.MapGet("/identity-resources", (IMediator mediator) => mediator.Send(new IdentityResourcesRequest()));
        debug.MapGet("/user-claims/{userId}", (string userId, IMediator mediator) => mediator.Send(new UserClaimsByUserIdRequest(userId)));
        debug.MapGet("/all-users", (IMediator mediator) => mediator.Send(new AllUsersRequest()));
        debug.MapGet("/find-user-by-subject/{subject}", (string subject, IMediator mediator) => mediator.Send(new FindUserBySubjectRequest(subject)));

        // Special checks
        debug.MapGet("/check-subject-3b9262de", (IMediator mediator) => mediator.Send(new CheckSpecificSubjectRequest()));
        debug.MapGet("/demo1-troubleshoot", (IMediator mediator) => mediator.Send(new Demo1TroubleshootRequest()));

        // Client cookie configuration status
        debug.MapGet("/client-cookie-config", (IClientCookieConfigurationService cookieService, ILogger<Program> logger) =>
        {
            logger.LogInformation("?? Checking client cookie configurations");

            var allConfigs = cookieService.GetAllClientConfigurations();
            var testClients = new[] { "mrwho_admin_web", "mrwho_demo1", "postman_client", "some_dynamic_client" };
            var results = new List<object>();

            foreach (var clientId in testClients)
            {
                var hasStatic = cookieService.HasStaticConfiguration(clientId);
                var usesDynamic = cookieService.UsesDynamicCookies(clientId);
                var schemeName = cookieService.GetCookieSchemeForClient(clientId);
                var cookieName = cookieService.GetCookieNameForClient(clientId);

                results.Add(new
                {
                    ClientId = clientId,
                    HasStaticConfiguration = hasStatic,
                    UsesDynamicCookies = usesDynamic,
                    SchemeName = schemeName,
                    CookieName = cookieName,
                    Status = hasStatic ? "? STATIC" : "?? DYNAMIC"
                });
            }

            return Results.Json(new
            {
                Title = "Client Cookie Configuration Analysis",
                AllStaticConfigurations = allConfigs.Select(kvp => new
                {
                    kvp.Key,
                    kvp.Value.ClientId,
                    kvp.Value.SchemeName,
                    kvp.Value.CookieName
                }),
                TestResults = results,
                Summary = new
                {
                    StaticClients = results.Count(r => ((dynamic)r).HasStaticConfiguration),
                    DynamicClients = results.Count(r => ((dynamic)r).UsesDynamicCookies),
                    ExpectedBehavior = "Demo1 should now show as STATIC (not DYNAMIC)"
                }
            });
        });

        // Test dynamic vs static cookie approach
        debug.MapGet("/test-dynamic-cookies", async (
            IDynamicCookieService dynamicCookieService,
            IClientCookieConfigurationService cookieConfigService,
            ILogger<Program> logger,
            HttpContext context) =>
        {
            logger.LogInformation("?? Testing dynamic vs static cookie approaches");

            var testClients = new[] { "mrwho_admin_web", "mrwho_demo1", "postman_client" };
            var results = new List<object>();

            foreach (var clientId in testClients)
            {
                try
                {
                    var hasStatic = cookieConfigService.HasStaticConfiguration(clientId);
                    var isAuthenticated = await dynamicCookieService.IsAuthenticatedForClientAsync(clientId);
                    var principal = await dynamicCookieService.GetClientPrincipalAsync(clientId);

                    var subjectClaim = principal?.FindFirst(ClaimTypes.NameIdentifier) ??
                                      principal?.FindFirst(OpenIddictConstants.Claims.Subject);

                    results.Add(new
                    {
                        ClientId = clientId,
                        HasStaticConfig = hasStatic,
                        IsAuthenticated = isAuthenticated,
                        HasPrincipal = principal != null,
                        SubjectClaim = subjectClaim != null ? new
                        {
                            Type = subjectClaim.Type,
                            Value = subjectClaim.Value
                        } : null,
                        AllClaims = principal?.Claims.Select(c => new { c.Type, c.Value }).ToArray() ?? new object[0],
                        CookieName = cookieConfigService.GetCookieNameForClient(clientId),
                        SchemeName = cookieConfigService.GetCookieSchemeForClient(clientId),
                        Status = hasStatic ? "?? STATIC" : "?? DYNAMIC"
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new
                    {
                        ClientId = clientId,
                        Error = ex.Message,
                        Status = "? ERROR"
                    });
                }
            }

            return Results.Json(new
            {
                Title = "Dynamic vs Static Cookie Test",
                TestResults = results,
                Notes = new
                {
                    Demo1Status = "Demo1 should now use DYNAMIC approach",
                    SubjectClaimTypes = new
                    {
                        NameIdentifier = ClaimTypes.NameIdentifier,
                        Subject = OpenIddictConstants.Claims.Subject
                    }
                }
            });
        });

        // Test back-channel logout system
        debug.MapPost("/test-backchannel-logout", async (
            HttpContext context,
            IBackChannelLogoutService backChannelService,
            IOpenIddictAuthorizationManager authorizationManager,
            ILogger<Program> logger,
            [FromBody] TestBackChannelRequest request) =>
        {
            if (!app.Environment.IsDevelopment())
            {
                return Results.BadRequest("This endpoint is only available in development");
            }

            logger.LogInformation("?? Testing back-channel logout for authorization {AuthorizationId}", request.AuthorizationId);

            try
            {
                await backChannelService.NotifyClientLogoutAsync(request.AuthorizationId, request.Subject, request.SessionId);

                return Results.Ok(new
                {
                    Success = true,
                    Message = "Back-channel logout notification sent successfully",
                    AuthorizationId = request.AuthorizationId,
                    Subject = request.Subject,
                    SessionId = request.SessionId,
                    Timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error testing back-channel logout");
                return Results.Problem($"Error testing back-channel logout: {ex.Message}");
            }
        });

        // ?? NEW: Device Management Debug Endpoint
        debug.MapGet("/device-management-status", async (
            ApplicationDbContext context,
            IDeviceManagementService deviceService,
            ILogger<Program> logger) =>
        {
            if (!app.Environment.IsDevelopment())
            {
                return Results.BadRequest("This endpoint is only available in development");
            }

            logger.LogInformation("?? Checking device management system status");

            try
            {
                // Check if device tables exist
                var hasUserDevices = false;
                var hasPersistentQrSessions = false;
                var hasDeviceAuthLogs = false;
                var deviceCount = 0;
                var qrSessionCount = 0;
                var authLogCount = 0;

                try
                {
                    deviceCount = await context.UserDevices.CountAsync();
                    hasUserDevices = true;
                }
                catch { /* Table doesn't exist */ }

                try
                {
                    qrSessionCount = await context.PersistentQrSessions.CountAsync();
                    hasPersistentQrSessions = true;
                }
                catch { /* Table doesn't exist */ }

                try
                {
                    authLogCount = await context.DeviceAuthenticationLogs.CountAsync();
                    hasDeviceAuthLogs = true;
                }
                catch { /* Table doesn't exist */ }

                return Results.Json(new
                {
                    Title = "?? Device Management System Status",
                    DatabaseStatus = new
                    {
                        UserDevicesTable = hasUserDevices ? "? Available" : "? Missing",
                        PersistentQrSessionsTable = hasPersistentQrSessions ? "? Available" : "? Missing",
                        DeviceAuthenticationLogsTable = hasDeviceAuthLogs ? "? Available" : "? Missing"
                    },
                    DataCounts = new
                    {
                        RegisteredDevices = deviceCount,
                        QrSessions = qrSessionCount,
                        AuthenticationLogs = authLogCount
                    },
                    SystemStatus = hasUserDevices && hasPersistentQrSessions && hasDeviceAuthLogs ? 
                        "?? Device Management System is operational" : 
                        "?? Device Management System needs database setup",
                    Endpoints = new
                    {
                        DeviceManagementUI = "/device-management",
                        DeviceRegistration = "/device-management/register",
                        DeviceAPI = "/api/devices",
                        QrLoginSession = "/qr-login/start?persistent=true",
                        QrLoginPersistent = "/qr-login/start?persistent=true"
                    },
                    Instructions = hasUserDevices ? (object)new
                    {
                        NextSteps = new[]
                        {
                            "1. Visit /device-management/register to register your first device",
                            "2. Try enhanced QR login at /qr-login/start?persistent=true",
                            "3. View device activity at /device-management/activity",
                            "4. Test API endpoints at /api/devices"
                        }
                    } : new
                    {
                        SetupRequired = new[]
                        {
                            "? Database tables missing - this is expected due to SQL Server cascade constraints",
                            "? Solution: The system will automatically recreate tables on next startup",
                            "?? Alternative: Restart the application to trigger EnsureCreated fallback",
                            "?? The device management system is designed to handle this gracefully"
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error checking device management status");
                return Results.Problem($"Error checking device management status: {ex.Message}");
            }
        });

        return app;
    }

    /// <summary>
    /// Request model for testing back-channel logout
    /// </summary>
    public class TestBackChannelRequest
    {
        public string AuthorizationId { get; set; } = "";
        public string Subject { get; set; } = "";
        public string SessionId { get; set; } = "";
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
        else
        {
            // For development and production: Use migrations with error handling
            logger.LogInformation("Using migrations for database setup (Environment: {Environment})", app.Environment.EnvironmentName);
            
            if (!shouldSkipMigrations)
            {
                try
                {
                    // Check if database exists, if not create it with migrations
                    var pendingMigrations = await context.Database.GetPendingMigrationsAsync();
                    if (pendingMigrations.Any())
                    {
                        logger.LogInformation("Applying {Count} pending migrations: {Migrations}", 
                            pendingMigrations.Count(), string.Join(", ", pendingMigrations));
                        
                        // Apply migrations with retry logic for constraint conflicts
                        await ApplyMigrationsWithRetryAsync(context, logger);
                        
                        Console.WriteLine($"Applied {pendingMigrations.Count()} pending migrations");
                    }
                    else
                    {
                        logger.LogInformation("Database is up to date");
                        Console.WriteLine("Database is up to date - no migrations needed");
                    }
                }
                catch (Exception ex) when (ex.Message.Contains("multiple cascade paths") || ex.Message.Contains("cycles"))
                {
                    // Handle SQL Server cascade constraint issues gracefully
                    logger.LogWarning("Migration failed due to cascade constraints. Attempting to recreate database with EnsureCreated: {Error}", ex.Message);
                    
                    try
                    {
                        // Fall back to EnsureCreated for initial setup
                        await context.Database.EnsureDeletedAsync();
                        await context.Database.EnsureCreatedAsync();
                        Console.WriteLine("Database recreated using EnsureCreated due to migration constraints");
                        
                        // Log this as a known issue
                        logger.LogInformation("?? Device Management tables created successfully with EnsureCreated fallback");
                    }
                    catch (Exception fallbackEx)
                    {
                        logger.LogError(fallbackEx, "Failed to create database even with EnsureCreated fallback");
                        throw;
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error applying database migrations");
                    throw;
                }
            }
            else
            {
                logger.LogInformation("Skipping migrations as requested by configuration");
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

        // Initialize standard identity resources
        try
        {
            await scopeSeederService.InitializeStandardIdentityResourcesAsync();
            Console.WriteLine("Standard identity resources initialized successfully in database");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing standard identity resources: {ex.Message}");
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
            var result = await userManager.CreateAsync(testUser, "Test123!");
            if (result.Succeeded)
            {
                // Add name claims to test user
                await userManager.AddClaimAsync(testUser, new System.Security.Claims.Claim("name", "John Doe"));
                await userManager.AddClaimAsync(testUser, new System.Security.Claims.Claim("given_name", "John"));
                await userManager.AddClaimAsync(testUser, new System.Security.Claims.Claim("family_name", "Doe"));
                await userManager.AddClaimAsync(testUser, new System.Security.Claims.Claim("preferred_username", "john.doe"));
                Console.WriteLine("Created test user with name claims");
            }
        }

        // Create additional test users with different name scenarios
        if (!await context.Users.AnyAsync(u => u.UserName == "jane.smith@example.com"))
        {
            var janeUser = new IdentityUser 
            { 
                UserName = "jane.smith@example.com", 
                Email = "jane.smith@example.com", 
                EmailConfirmed = true 
            };
            var result = await userManager.CreateAsync(janeUser, "Test123!");
            if (result.Succeeded)
            {
                // Add name claims to Jane
                await userManager.AddClaimAsync(janeUser, new System.Security.Claims.Claim("name", "Jane Smith"));
                await userManager.AddClaimAsync(janeUser, new System.Security.Claims.Claim("given_name", "Jane"));
                await userManager.AddClaimAsync(janeUser, new System.Security.Claims.Claim("family_name", "Smith"));
                await userManager.AddClaimAsync(janeUser, new System.Security.Claims.Claim("preferred_username", "jane.smith"));
                Console.WriteLine("Created Jane Smith test user with name claims");
            }
        }

        // Create a test user without name claims to test email-based fallback
        if (!await context.Users.AnyAsync(u => u.UserName == "bob.wilson@example.com"))
        {
            var bobUser = new IdentityUser 
            { 
                UserName = "bob.wilson@example.com", 
                Email = "bob.wilson@example.com", 
                EmailConfirmed = true 
            };
            var result = await userManager.CreateAsync(bobUser, "Test123!");
            if (result.Succeeded)
            {
                // Intentionally not adding name claims to test email-based fallback
                // The GetUserDisplayName method should convert "bob.wilson@example.com" to "Bob Wilson"
                Console.WriteLine("Created Bob Wilson test user without name claims (for email-based fallback testing)");
            }
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
    /// Applies migrations with retry logic for SQL Server constraint issues
    /// </summary>
    private static async Task ApplyMigrationsWithRetryAsync(ApplicationDbContext context, ILogger logger)
    {
        const int maxRetries = 3;
        int retryCount = 0;

        while (retryCount < maxRetries)
        {
            try
            {
                await context.Database.MigrateAsync();
                return; // Success
            }
            catch (Exception ex) when (ex.Message.Contains("multiple cascade paths") || ex.Message.Contains("cycles"))
            {
                retryCount++;
                logger.LogWarning("Migration attempt {Retry} failed due to cascade constraints: {Error}", retryCount, ex.Message);

                if (retryCount >= maxRetries)
                {
                    // Final attempt: try to clean up and recreate
                    logger.LogWarning("All migration attempts failed. This is expected for the new device management tables due to SQL Server cascade constraints.");
                    throw; // Re-throw to be caught by the outer handler
                }

                // Wait before retrying
                await Task.Delay(1000);
            }
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