using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using MrWho.Data;
using MrWho.Models;
using Microsoft.AspNetCore.Identity;

namespace MrWho.Services;

/// <summary>
/// Service for managing dynamic OIDC client configurations
/// </summary>
public interface IOidcClientService
{
    Task InitializeEssentialDataAsync();
    Task InitializeDefaultRealmAndClientsAsync();
    Task<IEnumerable<Client>> GetEnabledClientsAsync();
    Task SyncClientWithOpenIddictAsync(Client client);
}

/// <summary>
/// Service for seeding sample realm and client data
/// </summary>
public interface ISeedingService
{
    Task SeedSampleDataAsync(bool recreateData = false);
    Task SeedRealmsAsync();
    Task SeedClientsAsync();
    Task CleanupSampleDataAsync();
}

public class OidcClientService : IOidcClientService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<OidcClientService> _logger;

    public OidcClientService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        UserManager<IdentityUser> userManager,
        ILogger<OidcClientService> logger)
    {
        _context = context;
        _applicationManager = applicationManager;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Initialize essential data that must always be present (admin realm, admin client, admin user)
    /// </summary>
    public async Task InitializeEssentialDataAsync()
    {
        // 1. Create admin realm if it doesn't exist
        var adminRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "admin");
        if (adminRealm == null)
        {
            adminRealm = new Realm
            {
                Name = "admin",
                DisplayName = "MrWho Administration",
                Description = "Administrative realm for MrWho OIDC server management",
                IsEnabled = true,
                AccessTokenLifetime = TimeSpan.FromMinutes(60),
                RefreshTokenLifetime = TimeSpan.FromDays(30),
                AuthorizationCodeLifetime = TimeSpan.FromMinutes(10),
                CreatedBy = "System"
            };
            _context.Realms.Add(adminRealm);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created admin realm");
        }

        // 2. Create admin client for MrWhoAdmin.Web if it doesn't exist
        var adminClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web");

        if (adminClient == null)
        {
            adminClient = new Client
            {
                ClientId = "mrwho_admin_web",
                ClientSecret = "MrWhoAdmin2024!SecretKey",
                Name = "MrWho Admin Web Application",
                Description = "Official web administration interface for MrWho OIDC server",
                RealmId = adminRealm.Id,
                IsEnabled = true,
                ClientType = ClientType.Confidential,
                AllowAuthorizationCodeFlow = true,
                AllowClientCredentialsFlow = false,
                AllowPasswordFlow = false,
                AllowRefreshTokenFlow = true,
                RequirePkce = true,
                RequireClientSecret = true,
                CreatedBy = "System"
            };

            _context.Clients.Add(adminClient);
            await _context.SaveChangesAsync();

            // Add redirect URIs for MrWhoAdmin.Web (port 7257)
            var redirectUris = new[]
            {
                "https://localhost:7257/signin-oidc",
                "https://localhost:7257/callback"
            };

            foreach (var uri in redirectUris)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = adminClient.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs
            var postLogoutUris = new[]
            {
                "https://localhost:7257/",
                "https://localhost:7257/signout-callback-oidc"
            };

            foreach (var uri in postLogoutUris)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                {
                    ClientId = adminClient.Id,
                    Uri = uri
                });
            }

            // Add scopes (INCLUDING API SCOPES)
            var scopes = new[] { "openid", "email", "profile", "roles", "api.read", "api.write" };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = adminClient.Id,
                    Scope = scope
                });
            }

            // Add permissions (INCLUDING API PERMISSIONS)
            var permissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "oidc:scope:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                "oidc:scope:api.read",   // Use oidc:scope: prefix for API read permission
                "oidc:scope:api.write"   // Use oidc:scope: prefix for API write permission
            };

            foreach (var permission in permissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = adminClient.Id,
                    Permission = permission
                });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created admin client 'mrwho_admin_web' with API access");
        }
        else
        {
            // Check if existing admin client has API scopes and add them if missing
            var existingApiScopes = adminClient.Scopes.Where(s => s.Scope.StartsWith("api.")).ToList();
            var existingCorrectApiPermissions = adminClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:api.")).ToList();

            // Fix existing incorrect permissions - remove old format and add correct format
            var oldApiPermissions = adminClient.Permissions.Where(p => p.Permission.StartsWith("api.") && !p.Permission.StartsWith("oidc:scope:")).ToList();
            if (oldApiPermissions.Any())
            {
                _logger.LogInformation("Removing old API permissions with incorrect format");
                foreach (var oldPermission in oldApiPermissions)
                {
                    _context.ClientPermissions.Remove(oldPermission);
                }
            }

            if (existingApiScopes.Count == 0)
            {
                _logger.LogInformation("Adding API scopes to existing admin client");
                
                // Add API scopes
                var apiScopes = new[] { "api.read", "api.write" };
                foreach (var scope in apiScopes)
                {
                    _context.ClientScopes.Add(new ClientScope
                    {
                        ClientId = adminClient.Id,
                        Scope = scope
                    });
                }
            }

            if (existingCorrectApiPermissions.Count == 0)
            {
                _logger.LogInformation("Adding API permissions with correct format to existing admin client");
                
                // Add API permissions with correct oidc:scope: prefix
                var apiPermissions = new[] { "oidc:scope:api.read", "oidc:scope:api.write" };
                foreach (var permission in apiPermissions)
                {
                    _context.ClientPermissions.Add(new ClientPermission
                    {
                        ClientId = adminClient.Id,
                        Permission = permission
                    });
                }
            }

            if (existingApiScopes.Count == 0 || existingCorrectApiPermissions.Count == 0 || oldApiPermissions.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated API scopes and permissions on existing admin client");
                
                // Reload the client with new scopes and permissions
                adminClient = await _context.Clients
                    .Include(c => c.RedirectUris)
                    .Include(c => c.PostLogoutUris)
                    .Include(c => c.Scopes)
                    .Include(c => c.Permissions)
                    .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web");
            }
        }

        // 3. Create admin user if it doesn't exist
        var adminUser = await _userManager.FindByNameAsync("admin@mrwho.local");
        if (adminUser == null)
        {
            adminUser = new IdentityUser
            {
                UserName = "admin@mrwho.local",
                Email = "admin@mrwho.local",
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(adminUser, "MrWhoAdmin2024!");
            if (result.Succeeded)
            {
                _logger.LogInformation("Created admin user 'admin@mrwho.local'");
            }
            else
            {
                _logger.LogError("Failed to create admin user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }

        // Sync the admin client with OpenIddict
        await SyncClientWithOpenIddictAsync(adminClient!);
        
        // CRITICAL FIX: Clean up any existing incorrect API permissions and ensure correct ones are present
        await FixExistingApiPermissionsAsync(adminClient!);
    }

    public async Task InitializeDefaultRealmAndClientsAsync()
    {
        // Create default realm if it doesn't exist
        var defaultRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "default");
        if (defaultRealm == null)
        {
            defaultRealm = new Realm
            {
                Name = "default",
                DisplayName = "Default Realm",
                Description = "Default realm for OIDC clients",
                IsEnabled = true,
                CreatedBy = "System"
            };
            _context.Realms.Add(defaultRealm);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default realm");
        }

        // Create default client if it doesn't exist (keeping existing postman_client for backwards compatibility)
        var defaultClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)  
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "postman_client");

        if (defaultClient == null)
        {
            defaultClient = new Client
            {
                ClientId = "postman_client",
                ClientSecret = "postman_secret",
                Name = "Postman Test Client",
                Description = "Default test client for development",
                RealmId = defaultRealm.Id,
                IsEnabled = true,
                ClientType = ClientType.Confidential,
                AllowAuthorizationCodeFlow = true,
                AllowClientCredentialsFlow = true,
                AllowPasswordFlow = true,
                AllowRefreshTokenFlow = true,
                RequirePkce = false,
                RequireClientSecret = true,
                CreatedBy = "System"
            };

            _context.Clients.Add(defaultClient);
            await _context.SaveChangesAsync();

            // Add redirect URIs
            var redirectUris = new[]
            {
                "https://localhost:7001/callback",
                "http://localhost:5001/callback",
                "https://localhost:7002/",
                "https://localhost:7002/callback",
                "https://localhost:7002/signin-oidc"
            };

            foreach (var uri in redirectUris)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = defaultClient.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs
            var postLogoutUris = new[]
            {
                "https://localhost:7001/",
                "http://localhost:5001/",
                "https://localhost:7002/",
                "https://localhost:7002/signout-callback-oidc"
            };

            foreach (var uri in postLogoutUris)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                {
                    ClientId = defaultClient.Id,
                    Uri = uri
                });
            }

            // Add scopes
            var scopes = new[] { "openid", "email", "profile", "roles" };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = defaultClient.Id,
                    Scope = scope
                });
            }

            // Add permissions
            var permissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "oidc:scope:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            };

            foreach (var permission in permissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = defaultClient.Id,
                    Permission = permission
                });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default client 'postman_client'");
        }

        // Sync all enabled clients with OpenIddict
        var enabledClients = await GetEnabledClientsAsync();
        foreach (var client in enabledClients)
        {
            await SyncClientWithOpenIddictAsync(client);
        }
    }

    public async Task<IEnumerable<Client>> GetEnabledClientsAsync()
    {
        return await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Where(c => c.IsEnabled && c.Realm.IsEnabled)
            .ToListAsync();
    }

    public async Task SyncClientWithOpenIddictAsync(Client client)
    {
        try
        {
            // Remove existing OpenIddict application if it exists
            var existingClient = await _applicationManager.FindByClientIdAsync(client.ClientId);
            if (existingClient != null)
            {
                await _applicationManager.DeleteAsync(existingClient);
            }

            // Create new OpenIddict application descriptor
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                DisplayName = client.Name,
                ClientType = client.ClientType == ClientType.Public 
                    ? OpenIddictConstants.ClientTypes.Public 
                    : OpenIddictConstants.ClientTypes.Confidential
            };

            // Add permissions based on client configuration
            if (client.AllowAuthorizationCodeFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
            }

            if (client.AllowClientCredentialsFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            }

            if (client.AllowPasswordFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
            }

            if (client.AllowRefreshTokenFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
            }

            // Always add token endpoint
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            // Add scope permissions based on client scopes
            foreach (var scope in client.Scopes)
            {
                switch (scope.Scope.ToLower())
                {
                    case "openid":
                        descriptor.Permissions.Add("oidc:scope:openid");
                        break;
                    case "email":
                        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
                        break;
                    case "profile":
                        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
                        break;
                    case "roles":
                        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Roles);
                        break;
                    case "api.read":
                        descriptor.Permissions.Add("oidc:scope:api.read");
                        break;
                    case "api.write":
                        descriptor.Permissions.Add("oidc:scope:api.write");
                        break;
                    default:
                        // For custom scopes, add them with the oidc:scope: prefix
                        descriptor.Permissions.Add($"oidc:scope:{scope.Scope}");
                        break;
                }
            }

            // IMPORTANT: Also add the endpoint access for UserInfo if we have openid scope 
            if (client.Scopes.Any(s => s.Scope == "openid"))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
            }

            // Add additional permissions from client permissions (but skip the ones we're handling above)
            foreach (var permission in client.Permissions)
            {
                // Skip scope permissions as they are handled above, and skip old incorrect API permissions
                if (!permission.Permission.StartsWith("oidc:scope:") && 
                    !permission.Permission.StartsWith("api.") &&
                    !descriptor.Permissions.Contains(permission.Permission))
                {
                    descriptor.Permissions.Add(permission.Permission);
                }
            }

            // Add redirect URIs
            foreach (var redirectUri in client.RedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(redirectUri.Uri));
            }

            // Add post-logout redirect URIs
            foreach (var postLogoutUri in client.PostLogoutUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutUri.Uri));
            }

            // Create the OpenIddict application
            await _applicationManager.CreateAsync(descriptor);

            _logger.LogInformation("Successfully synced client '{ClientId}' with OpenIddict. Permissions: {Permissions}", 
                client.ClientId, string.Join(", ", descriptor.Permissions));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync client '{ClientId}' with OpenIddict", client.ClientId);
            throw;
        }
    }

    private async Task FixExistingApiPermissionsAsync(Client client)
    {
        // Ensure any existing API permissions are corrected to the new format
        var apiScopes = new[] { "api.read", "api.write" };
        var correctApiPermissions = apiScopes.Select(scope => $"oidc:scope:{scope}").ToList();

        // Remove old API permissions without oidc:scope: prefix
        var oldApiPermissions = client.Permissions
            .Where(p => p.Permission.StartsWith("api.") && !p.Permission.StartsWith("oidc:scope:"))
            .ToList();

        // Remove old API permissions
        if (oldApiPermissions.Any())
        {
            _logger.LogInformation("Removing old API permissions with incorrect format for client '{ClientId}'", client.ClientId);
            foreach (var oldPermission in oldApiPermissions)
            {
                _context.ClientPermissions.Remove(oldPermission);
            }
        }

        // Add missing correct API permissions
        var missingApiPermissions = correctApiPermissions
            .Where(p => !client.Permissions.Any(cp => cp.Permission == p))
            .ToList();

        if (missingApiPermissions.Any())
        {
            _logger.LogInformation("Adding missing correct API permissions for client '{ClientId}': {Permissions}", client.ClientId, string.Join(", ", missingApiPermissions));
            foreach (var permission in missingApiPermissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = client.Id,
                    Permission = permission
                });
            }
        }

        await _context.SaveChangesAsync();
        _logger.LogInformation("Successfully fixed API permissions for client '{ClientId}'", client.ClientId);
    }
}

public class SeedingService : ISeedingService
{
    private readonly ApplicationDbContext _context;
    private readonly IOidcClientService _oidcClientService;
    private readonly ILogger<SeedingService> _logger;

    public SeedingService(
        ApplicationDbContext context,
        IOidcClientService oidcClientService,
        ILogger<SeedingService> logger)
    {
        _context = context;
        _oidcClientService = oidcClientService;
        _logger = logger;
    }

    public async Task SeedSampleDataAsync(bool recreateData = false)
    {
        if (recreateData)
        {
            await CleanupSampleDataAsync();
        }

        // Check if sample data already exists
        var existingSampleRealms = await _context.Realms
            .Where(r => r.Name.StartsWith("sample-") || r.Name.StartsWith("demo-"))
            .CountAsync();

        if (existingSampleRealms > 0 && !recreateData)
        {
            _logger.LogInformation("Sample data already exists. Skipping seeding.");
            return;
        }

        _logger.LogInformation("Starting sample data seeding...");

        await SeedRealmsAsync();
        await SeedClientsAsync();

        _logger.LogInformation("Sample data seeding completed successfully");
    }

    public async Task SeedRealmsAsync()
    {
        var sampleRealms = new[]
        {
            new Realm
            {
                Name = "sample-development",
                DisplayName = "Development Environment",
                Description = "Sample realm for development and testing purposes",
                IsEnabled = true,
                AccessTokenLifetime = TimeSpan.FromMinutes(30),
                RefreshTokenLifetime = TimeSpan.FromDays(7),
                AuthorizationCodeLifetime = TimeSpan.FromMinutes(5),
                CreatedBy = "SeedingService"
            },
            new Realm
            {
                Name = "sample-staging",
                DisplayName = "Staging Environment",
                Description = "Sample realm for staging and pre-production testing",
                IsEnabled = true,
                AccessTokenLifetime = TimeSpan.FromMinutes(60),
                RefreshTokenLifetime = TimeSpan.FromDays(14),
                AuthorizationCodeLifetime = TimeSpan.FromMinutes(10),
                CreatedBy = "SeedingService"
            },
            new Realm
            {
                Name = "demo-multi-tenant",
                DisplayName = "Multi-Tenant Demo",
                Description = "Demo realm showcasing multi-tenant capabilities",
                IsEnabled = true,
                AccessTokenLifetime = TimeSpan.FromMinutes(45),
                RefreshTokenLifetime = TimeSpan.FromDays(21),
                AuthorizationCodeLifetime = TimeSpan.FromMinutes(8),
                CreatedBy = "SeedingService"
            }
        };

        foreach (var realm in sampleRealms)
        {
            var existingRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == realm.Name);
            if (existingRealm == null)
            {
                _context.Realms.Add(realm);
                _logger.LogInformation("Added sample realm: {RealmName}", realm.Name);
            }
        }

        await _context.SaveChangesAsync();
    }

    public async Task SeedClientsAsync()
    {
        // Get the seeded realms
        var developmentRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "sample-development");
        var stagingRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "sample-staging");
        var demoRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "demo-multi-tenant");

        if (developmentRealm == null || stagingRealm == null || demoRealm == null)
        {
            _logger.LogWarning("Sample realms not found. Cannot seed clients.");
            return;
        }

        var sampleClients = new[]
        {
            // SPA Client for Development
            new ClientSeedData
            {
                Client = new Client
                {
                    ClientId = "spa-dev-app",
                    Name = "SPA Development App",
                    Description = "Single Page Application for development",
                    RealmId = developmentRealm.Id,
                    IsEnabled = true,
                    ClientType = ClientType.Public,
                    AllowAuthorizationCodeFlow = true,
                    AllowClientCredentialsFlow = false,
                    AllowPasswordFlow = false,
                    AllowRefreshTokenFlow = true,
                    RequirePkce = true,
                    RequireClientSecret = false,
                    CreatedBy = "SeedingService"
                },
                RedirectUris = new[]
                {
                    "http://localhost:3000/callback",
                    "http://localhost:3001/callback",
                    "https://localhost:3001/callback"
                },
                PostLogoutUris = new[]
                {
                    "http://localhost:3000/",
                    "https://localhost:3001/"
                },
                Scopes = new[] { "openid", "profile", "email", "roles" },
                Permissions = new[]
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    "oidc:scope:openid",
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
            },

            // Web Application for Staging
            new ClientSeedData
            {
                Client = new Client
                {
                    ClientId = "web-staging-app",
                    ClientSecret = "staging-web-secret-2024!",
                    Name = "Web Staging Application",
                    Description = "Server-side web application for staging environment",
                    RealmId = stagingRealm.Id,
                    IsEnabled = true,
                    ClientType = ClientType.Confidential,
                    AllowAuthorizationCodeFlow = true,
                    AllowClientCredentialsFlow = false,
                    AllowPasswordFlow = false,
                    AllowRefreshTokenFlow = true,
                    RequirePkce = false,
                    RequireClientSecret = true,
                    CreatedBy = "SeedingService"
                },
                RedirectUris = new[]
                {
                    "https://staging.example.com/signin-oidc",
                    "https://localhost:7200/signin-oidc"
                },
                PostLogoutUris = new[]
                {
                    "https://staging.example.com/",
                    "https://localhost:7200/"
                },
                Scopes = new[] { "openid", "profile", "email", "roles" },
                Permissions = new[]
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    "oidc:scope:openid",
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
            },

            // Machine-to-Machine Client
            new ClientSeedData
            {
                Client = new Client
                {
                    ClientId = "api-service-client",
                    ClientSecret = "api-service-secret-m2m-2024!",
                    Name = "API Service Client",
                    Description = "Machine-to-machine client for API services",
                    RealmId = developmentRealm.Id,
                    IsEnabled = true,
                    ClientType = ClientType.Machine,
                    AllowAuthorizationCodeFlow = false,
                    AllowClientCredentialsFlow = true,
                    AllowPasswordFlow = false,
                    AllowRefreshTokenFlow = false,
                    RequirePkce = false,
                    RequireClientSecret = true,
                    CreatedBy = "SeedingService"
                },
                RedirectUris = Array.Empty<string>(),
                PostLogoutUris = Array.Empty<string>(),
                Scopes = new[] { "api.read", "api.write" },
                Permissions = new[]
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
                }
            },

            // Mobile Application
            new ClientSeedData
            {
                Client = new Client
                {
                    ClientId = "mobile-demo-app",
                    Name = "Mobile Demo Application",
                    Description = "Mobile application for demonstration purposes",
                    RealmId = demoRealm.Id,
                    IsEnabled = true,
                    ClientType = ClientType.Public,
                    AllowAuthorizationCodeFlow = true,
                    AllowClientCredentialsFlow = false,
                    AllowPasswordFlow = false,
                    AllowRefreshTokenFlow = true,
                    RequirePkce = true,
                    RequireClientSecret = false,
                    CreatedBy = "SeedingService"
                },
                RedirectUris = new[]
                {
                    "com.example.mobileapp://callback",
                    "https://mobile-demo.example.com/callback"
                },
                PostLogoutUris = new[]
                {
                    "com.example.mobileapp://logout",
                    "https://mobile-demo.example.com/"
                },
                Scopes = new[] { "openid", "profile", "email", "offline_access" },
                Permissions = new[]
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    "oidc:scope:openid",
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
            }
        };

        foreach (var clientData in sampleClients)
        {
            var existingClient = await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == clientData.Client.ClientId);
            if (existingClient != null)
            {
                continue; // Skip if already exists
            }

            // Add the client
            _context.Clients.Add(clientData.Client);
            await _context.SaveChangesAsync(); // Save to get the ID

            // Add redirect URIs
            foreach (var uri in clientData.RedirectUris)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = clientData.Client.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs
            foreach (var uri in clientData.PostLogoutUris)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                {
                    ClientId = clientData.Client.Id,
                    Uri = uri
                });
            }

            // Add scopes
            foreach (var scope in clientData.Scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = clientData.Client.Id,
                    Scope = scope
                });
            }

            // Add permissions
            foreach (var permission in clientData.Permissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = clientData.Client.Id,
                    Permission = permission
                });
            }

            _logger.LogInformation("Added sample client: {ClientId}", clientData.Client.ClientId);
        }

        await _context.SaveChangesAsync();

        // Sync enabled clients with OpenIddict
        var enabledSampleClients = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Where(c => c.IsEnabled && c.Realm.IsEnabled && c.CreatedBy == "SeedingService")
            .ToListAsync();

        foreach (var client in enabledSampleClients)
        {
            try
            {
                await _oidcClientService.SyncClientWithOpenIddictAsync(client);
                _logger.LogInformation("Synced sample client {ClientId} with OpenIddict", client.ClientId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to sync sample client {ClientId} with OpenIddict", client.ClientId);
            }
        }
    }

    public async Task CleanupSampleDataAsync()
    {
        _logger.LogInformation("Cleaning up existing sample data...");

        // Remove sample clients and their related data
        var sampleClients = await _context.Clients
            .Where(c => c.CreatedBy == "SeedingService")
            .ToListAsync();

        _context.Clients.RemoveRange(sampleClients);

        // Remove sample realms
        var sampleRealms = await _context.Realms
            .Where(r => r.CreatedBy == "SeedingService")
            .ToListAsync();

        _context.Realms.RemoveRange(sampleRealms);

        await _context.SaveChangesAsync();

        _logger.LogInformation("Sample data cleanup completed");
    }

    private class ClientSeedData
    {
        public Client Client { get; set; } = null!;
        public string[] RedirectUris { get; set; } = Array.Empty<string>();
        public string[] PostLogoutUris { get; set; } = Array.Empty<string>();
        public string[] Scopes { get; set; } = Array.Empty<string>();
        public string[] Permissions { get; set; } = Array.Empty<string>();
    }
}