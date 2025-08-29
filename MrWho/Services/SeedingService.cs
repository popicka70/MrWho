using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using MrWho.Services;
using OpenIddict.Abstractions;

namespace MrWho.Services;

public class SeedingService : ISeedingService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IOidcClientService _oidcClientService;
    private readonly IScopeSeederService _scopeSeederService;
    private readonly IApiResourceSeederService _apiResourceSeederService;
    private readonly IIdentityResourceSeederService _identityResourceSeederService;
    private readonly ILogger<SeedingService> _logger;
    private readonly IClaimTypeSeederService? _claimTypeSeederService;

    public SeedingService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOidcClientService oidcClientService,
        IScopeSeederService scopeSeederService,
        IApiResourceSeederService apiResourceSeederService,
        IIdentityResourceSeederService identityResourceSeederService,
        ILogger<SeedingService> logger,
        IClaimTypeSeederService? claimTypeSeederService = null)
    {
        _context = context;
        _applicationManager = applicationManager;
        _userManager = userManager;
        _roleManager = roleManager;
        _oidcClientService = oidcClientService;
        _scopeSeederService = scopeSeederService;
        _apiResourceSeederService = apiResourceSeederService;
        _identityResourceSeederService = identityResourceSeederService;
        _logger = logger;
        _claimTypeSeederService = claimTypeSeederService;
    }

    public async Task SeedAsync()
    {
        // Schema managed via EF Core migrations on application startup.
        // No EnsureCreated calls here.
        
        // Seed default realm
        await SeedDefaultRealm();
        
        // Seed default roles
        await SeedDefaultRoles();
        
        // Seed default user
        await SeedDefaultUser();
        
        // Seed standard scopes
        await _scopeSeederService.InitializeStandardScopesAsync();
        
        // Seed standard API resources
        await _apiResourceSeederService.SeedStandardApiResourcesAsync();
        
        // Seed standard Identity resources
        await _identityResourceSeederService.SeedStandardIdentityResourcesAsync();

        // Seed claim types (after identity resources so we can also import distinct existing ones)
        if (_claimTypeSeederService != null)
        {
            await _claimTypeSeederService.SeedClaimTypesAsync();
        }
        
        // Seed predefined external identity providers (disabled by default)
        await SeedPredefinedIdentityProvidersAsync();
        
        // Seed default OIDC applications
        await SeedDefaultApplications();
    }

    private async Task SeedPredefinedIdentityProvidersAsync()
    {
        try
        {
            if (!await _context.Database.CanConnectAsync())
            {
                return;
            }

            foreach (var t in MrWho.Shared.PredefinedIdentityProviders.Templates)
            {
                if (!await _context.IdentityProviders.AnyAsync(x => x.Name == t.Key))
                {
                    _context.IdentityProviders.Add(new IdentityProvider
                    {
                        Name = t.Key,
                        DisplayName = t.DisplayName,
                        Type = IdentityProviderType.Oidc,
                        IsEnabled = false,
                        Authority = t.Authority,
                        Scopes = t.DefaultScopes,
                        ResponseType = "code",
                        UsePkce = true,
                        GetClaimsFromUserInfoEndpoint = true,
                        Order = t.Order,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        CreatedBy = "SeedingService",
                        UpdatedBy = "SeedingService"
                    });
                    _logger.LogInformation("Seeded predefined IdP: {Name}", t.Key);
                }
            }

            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error seeding predefined identity providers");
        }
    }

    private async Task SeedDefaultRealm()
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
        }
    }

    private async Task SeedDefaultApplications()
    {
        // Get or create default realm
        var defaultRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "default");
        if (defaultRealm == null)
        {
            await SeedDefaultRealm();
            defaultRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "default");
        }

        // Create default client if it doesn't exist
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
                RealmId = defaultRealm!.Id,
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

            // Add redirect URIs, scopes, permissions etc.
            await _oidcClientService.SyncClientWithOpenIddictAsync(defaultClient);
            _logger.LogInformation("Created default client application");
        }
    }

    private async Task SeedDefaultRoles()
    {
        var defaultRoles = new Dictionary<string, string>
        {
            { "Administrator", "Full system administrator with all permissions" },
            { "User", "Standard user with basic permissions" },
            { "Manager", "Manager with elevated permissions for team management" },
            { "Viewer", "Read-only access to view system information" }
        };

        foreach (var (roleName, description) in defaultRoles)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                var role = new IdentityRole(roleName);
                var result = await _roleManager.CreateAsync(role);
                
                if (result.Succeeded)
                {
                    // Add description and enabled status as role claims
                    await _roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("description", description));
                    await _roleManager.AddClaimAsync(role, new System.Security.Claims.Claim("enabled", "true"));
                    
                    _logger.LogInformation("Created default role: {RoleName} with description: {Description}", roleName, description);
                }
                else
                {
                    _logger.LogError("Failed to create role {RoleName}: {Errors}", 
                        roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
    }

    private async Task SeedDefaultUser()
    {
        const string defaultEmail = "admin@mrwho.local";
        const string defaultPassword = "Adm1n#2025!G7x";

        var existing = await _userManager.FindByEmailAsync(defaultEmail);
        if (existing == null)
        {
            var user = new IdentityUser
            {
                UserName = defaultEmail,
                Email = defaultEmail,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, defaultPassword);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Administrator");
                _logger.LogInformation("Created default admin user: {Email}", defaultEmail);

                // Ensure profile (ACTIVE so admin can log in immediately)
                if (!await _context.UserProfiles.AnyAsync(p => p.UserId == user.Id))
                {
                    _context.UserProfiles.Add(new UserProfile
                    {
                        UserId = user.Id,
                        DisplayName = "System Administrator",
                        State = UserState.Active,
                        CreatedAt = DateTime.UtcNow
                    });
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Created ACTIVE user profile for admin user {UserId}", user.Id);
                }
            }
            else
            {
                _logger.LogError("Failed to create default user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            // Backfill profile if missing (set Active for admin)
            if (!await _context.UserProfiles.AnyAsync(p => p.UserId == existing.Id))
            {
                _context.UserProfiles.Add(new UserProfile
                {
                    UserId = existing.Id,
                    DisplayName = "System Administrator",
                    State = UserState.Active,
                    CreatedAt = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
                _logger.LogInformation("Backfilled ACTIVE user profile for existing admin user {UserId}", existing.Id);
            }
        }
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
                Description = "Sample realm for staging and pre testing",
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