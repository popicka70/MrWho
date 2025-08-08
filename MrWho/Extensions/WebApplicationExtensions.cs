using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Services;
using MrWho.Middleware;
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

        app.UseHttpsRedirection();
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
        // OIDC Authorization endpoint
        app.MapGet("/connect/authorize", async (HttpContext context, IOidcAuthorizationHandler authorizationHandler) =>
        {
            return await authorizationHandler.HandleAuthorizationRequestAsync(context);
        });

        app.MapPost("/connect/authorize", async (HttpContext context, IOidcAuthorizationHandler authorizationHandler) =>
        {
            return await authorizationHandler.HandleAuthorizationRequestAsync(context);
        });

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
        // Debug endpoints discovery
        app.MapGet("/debug", () => Results.Ok(new
        {
            Title = "MrWho Identity Server Debug Endpoints",
            Endpoints = new
            {
                TokenInspector = "/identity/token-inspector",
                TokenInspectorAlt = "/identity/tokeninspector",
                ClientInfo = "/debug/client-info", 
                AdminClientInfo = "/debug/admin-client-info",
                Demo1ClientInfo = "/debug/demo1-client-info",
                EssentialData = "/debug/essential-data",
                ClientPermissions = "/debug/client-permissions",
                OpenIddictScopes = "/debug/openiddict-scopes",
                ClientCookieStatus = "/debug/client-cookies"
            },
            Documentation = "Visit any endpoint above for debug information or tools"
        }));

        // Debug endpoint for client cookie configurations
        app.MapGet("/debug/client-cookies", (HttpContext context, IClientCookieConfigurationService cookieService) =>
        {
            var configurations = cookieService.GetAllClientConfigurations();
            var currentClientId = context.Items["ClientId"]?.ToString();
            var currentScheme = context.Items["ClientCookieScheme"]?.ToString();
            var currentCookieName = context.Items["ClientCookieName"]?.ToString();

            var activeCookies = new List<object>();
            foreach (var config in configurations)
            {
                var cookieValue = context.Request.Cookies[config.Value.CookieName];
                activeCookies.Add(new
                {
                    ClientId = config.Key,
                    CookieName = config.Value.CookieName,
                    SchemeName = config.Value.SchemeName,
                    HasCookie = !string.IsNullOrEmpty(cookieValue),
                    CookieLength = cookieValue?.Length ?? 0
                });
            }

            return Results.Ok(new
            {
                CurrentRequest = new
                {
                    Path = context.Request.Path.ToString(),
                    ClientId = currentClientId,
                    CookieScheme = currentScheme,
                    CookieName = currentCookieName
                },
                ConfiguredClients = configurations.Select(kvp => new
                {
                    ClientId = kvp.Key,
                    SchemeName = kvp.Value.SchemeName,
                    CookieName = kvp.Value.CookieName
                }),
                ActiveCookies = activeCookies,
                AllRequestCookies = context.Request.Cookies.Select(c => new
                {
                    Name = c.Key,
                    Length = c.Value.Length
                }),
                Timestamp = DateTime.UtcNow
            });
        });

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

        app.MapGet("/debug/demo1-client-info", async (IOidcClientService oidcClientService) =>
        {
            var clients = await oidcClientService.GetEnabledClientsAsync();
            var demo1Client = clients.FirstOrDefault(c => c.ClientId == "mrwho_demo1");
            
            if (demo1Client == null)
            {
                return Results.NotFound("Demo1 client not found");
            }
            
            return Results.Ok(new
            {
                ClientId = demo1Client.ClientId,
                ClientSecret = demo1Client.ClientSecret,
                Name = demo1Client.Name,
                RealmName = demo1Client.Realm.Name,
                IsEnabled = demo1Client.IsEnabled,
                AuthorizeUrl = "https://localhost:7113/connect/authorize",
                TokenUrl = "https://localhost:7113/connect/token",
                LogoutUrl = "https://localhost:7113/connect/logout",
                RedirectUris = demo1Client.RedirectUris.Select(ru => ru.Uri).ToArray(),
                PostLogoutRedirectUris = demo1Client.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
                Scopes = demo1Client.Scopes.Select(s => s.Scope).ToArray(),
                SampleAuthUrl = $"https://localhost:7113/connect/authorize?client_id={demo1Client.ClientId}&response_type=code&redirect_uri=https://localhost:7037/signin-oidc&scope=openid%20email%20profile%20roles&state=demo1_test",
                SampleLogoutUrl = "https://localhost:7113/connect/logout?post_logout_redirect_uri=https://localhost:7037/signout-callback-oidc",
                Demo1Credentials = new
                {
                    Username = "demo1@example.com",
                    Password = "Demo123"
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
        app.MapPost("/debug/reset-admin-client", async (ApplicationDbContext context, IOidcClientService oidClientService, ILogger<Program> logger) =>
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
                await oidClientService.InitializeEssentialDataAsync();
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
 
        // Debug endpoint to test UserInfo handler directly
        app.MapGet("/debug/userinfo-test", async (HttpContext context, IUserInfoHandler userInfoHandler, ILogger<Program> logger) =>
        {
            logger.LogInformation("Testing UserInfo handler directly");
            
            if (!context.User.Identity?.IsAuthenticated == true)
            {
                return Results.Unauthorized();
            }
            
            try
            {
                var result = await userInfoHandler.HandleUserInfoRequestAsync(context);
                logger.LogInformation("UserInfo handler returned result type: {ResultType}", result.GetType().Name);
                return result;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error testing UserInfo handler");
                return Results.Problem($"Error testing UserInfo handler: {ex.Message}");
            }
        }).RequireAuthorization();

        // Debug endpoint to check current claims in ClaimsPrincipal
        app.MapGet("/debug/current-claims", (HttpContext context, ILogger<Program> logger) =>
        {
            logger.LogInformation("Checking current claims in ClaimsPrincipal");
            
            if (!context.User.Identity?.IsAuthenticated == true)
            {
                return Results.Json(new { IsAuthenticated = false, Message = "User is not authenticated" });
            }
            
            var claims = context.User.Claims.Select(c => new { Type = c.Type, Value = c.Value, Issuer = c.Issuer }).ToList();
            
            return Results.Json(new 
            { 
                IsAuthenticated = true,
                ClaimsCount = claims.Count,
                IdentityName = context.User.Identity?.Name,
                AuthenticationType = context.User.Identity?.AuthenticationType ?? string.Empty,
                Claims = claims
            });
        }).RequireAuthorization();

        // Debug endpoint to check identity resources in database
        app.MapGet("/debug/identity-resources", async (ApplicationDbContext context, ILogger<Program> logger) =>
        {
            logger.LogInformation("Checking identity resources in database");
            
            var identityResources = await context.IdentityResources
                .Include(ir => ir.UserClaims)
                .ToListAsync();

            var result = new
            {
                TotalIdentityResources = identityResources.Count,
                EnabledIdentityResources = identityResources.Count(ir => ir.IsEnabled),
                Resources = identityResources.Select(ir => new
                {
                    ir.Id,
                    ir.Name,
                    ir.DisplayName,
                    ir.Description,
                    ir.IsEnabled,
                    ir.IsRequired,
                    ir.IsStandard,
                    ClaimsCount = ir.UserClaims.Count,
                    Claims = ir.UserClaims.Select(c => c.ClaimType).ToArray()
                }).ToList(),
                Message = identityResources.Count == 0 
                    ? "No identity resources found - UserInfo handler will use scope-based fallback"
                    : $"Found {identityResources.Count} identity resources"
            };

            return Results.Json(result);
        });

        // Debug endpoint to check user claims for a specific user
        app.MapGet("/debug/user-claims/{userId}", async (string userId, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
        {
            logger.LogInformation("Checking claims for user {UserId}", userId);
            
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Results.NotFound($"User with ID '{userId}' not found");
            }

            var claims = await userManager.GetClaimsAsync(user);
            var roles = await userManager.GetRolesAsync(user);

            var result = new
            {
                UserId = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                ClaimsCount = claims.Count,
                Claims = claims.Select(c => new { Type = c.Type, Value = c.Value }).ToArray(),
                RolesCount = roles.Count,
                Roles = roles.ToArray()
            };

            return Results.Json(result);
        });

        // Debug endpoint to list all users in the system
        app.MapGet("/debug/all-users", async (UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
        {
            logger.LogInformation("Listing all users in the system");
            
            var users = userManager.Users.ToList();
            var userDetails = new List<object>();

            foreach (var user in users)
            {
                var claims = await userManager.GetClaimsAsync(user);
                var roles = await userManager.GetRolesAsync(user);
                var nameClaim = claims.FirstOrDefault(c => c.Type == "name")?.Value;

                userDetails.Add(new
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    EmailConfirmed = user.EmailConfirmed,
                    NameClaim = nameClaim,
                    ClaimsCount = claims.Count,
                    Claims = claims.Select(c => new { Type = c.Type, Value = c.Value }).ToArray(),
                    RolesCount = roles.Count,
                    Roles = roles.ToArray()
                });
            }

            var result = new
            {
                TotalUsers = users.Count,
                Users = userDetails
            };

            return Results.Json(result);
        });

        // Debug endpoint to check which user ID corresponds to the JWT subject
        app.MapGet("/debug/find-user-by-subject/{subject}", async (string subject, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
        {
            logger.LogInformation("Looking for user with subject/ID {Subject}", subject);
            
            var user = await userManager.FindByIdAsync(subject);
            if (user == null)
            {
                // Also try to find by username in case it's a username instead of ID
                user = await userManager.FindByNameAsync(subject);
            }

            if (user == null)
            {
                return Results.NotFound($"No user found with subject/ID or username '{subject}'");
            }

            var claims = await userManager.GetClaimsAsync(user);
            var nameClaim = claims.FirstOrDefault(c => c.Type == "name")?.Value;

            var result = new
            {
                UserId = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                NameClaim = nameClaim,
                ClaimsCount = claims.Count,
                Claims = claims.Select(c => new { Type = c.Type, Value = c.Value }).ToArray()
            };

            return Results.Json(result);
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