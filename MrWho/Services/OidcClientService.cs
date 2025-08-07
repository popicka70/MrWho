using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using Microsoft.AspNetCore.Identity;

namespace MrWho.Services;

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

        // 1.5. Create demo realm if it doesn't exist
        var demoRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "demo");
        if (demoRealm == null)
        {
            demoRealm = new Realm
            {
                Name = "demo",
                DisplayName = "Demo Applications",
                Description = "Realm for demo applications showcasing MrWho OIDC integration",
                IsEnabled = true,
                AccessTokenLifetime = TimeSpan.FromMinutes(60),
                RefreshTokenLifetime = TimeSpan.FromDays(7),
                AuthorizationCodeLifetime = TimeSpan.FromMinutes(10),
                CreatedBy = "System"
            };
            _context.Realms.Add(demoRealm);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created demo realm");
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

            // Add scopes (INCLUDING API SCOPES AND MRWHO.USE)
            var scopes = new[] { "openid", "email", "profile", "roles", "offline_access", "api.read", "api.write", "mrwho.use" };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = adminClient.Id,
                    Scope = scope
                });
            }

            // Add permissions (INCLUDING API PERMISSIONS AND MRWHO.USE)
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
                "oidc:scope:api.write",  // Use oidc:scope: prefix for API write permission
                "scp:mrwho.use"          // Use scp: prefix for custom mrwho.use permission
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
            var hasOfflineAccess = adminClient.Scopes.Any(s => s.Scope == "offline_access");
            var hasMrWhoUse = adminClient.Scopes.Any(s => s.Scope == "mrwho.use");

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

            if (!hasOfflineAccess)
            {
                _logger.LogInformation("Adding offline_access scope to existing admin client for refresh token support");
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = adminClient.Id,
                    Scope = "offline_access"
                });
            }

            if (!hasMrWhoUse)
            {
                _logger.LogInformation("Adding mrwho.use scope to existing admin client");
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = adminClient.Id,
                    Scope = "mrwho.use"
                });
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

            // Add mrwho.use permission if missing
            var hasMrWhoUsePermission = adminClient.Permissions.Any(p => p.Permission == "scp:mrwho.use");
            if (!hasMrWhoUsePermission)
            {
                _logger.LogInformation("Adding mrwho.use permission to existing admin client");
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = adminClient.Id,
                    Permission = "scp:mrwho.use"
                });
            }

            if (existingApiScopes.Count == 0 || existingCorrectApiPermissions.Count == 0 || !hasOfflineAccess || !hasMrWhoUse || !hasMrWhoUsePermission || oldApiPermissions.Any())
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

        // 2.5. Create demo1 client for MrWhoDemo1 if it doesn't exist
        var demo1Client = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_demo1");

        if (demo1Client == null)
        {
            demo1Client = new Client
            {
                ClientId = "mrwho_demo1",
                ClientSecret = "Demo1Secret2024!",
                Name = "MrWho Demo Application 1",
                Description = "Demo application showcasing MrWho OIDC integration",
                RealmId = demoRealm.Id,
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

            _context.Clients.Add(demo1Client);
            await _context.SaveChangesAsync();

            // Add redirect URIs for MrWhoDemo1 (port 7037)
            var redirectUris = new[]
            {
                "https://localhost:7037/signin-oidc",
                "https://localhost:7037/callback"
            };

            foreach (var uri in redirectUris)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = demo1Client.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs
            var postLogoutUris = new[]
            {
                "https://localhost:7037/",
                "https://localhost:7037/signout-callback-oidc"
            };

            foreach (var uri in postLogoutUris)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                {
                    ClientId = demo1Client.Id,
                    Uri = uri
                });
            }

            // Add scopes for demo1
            var scopes = new[] { "openid", "email", "profile", "roles", "offline_access" };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = demo1Client.Id,
                    Scope = scope
                });
            }

            // Add permissions for demo1
            var permissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "scp:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                "scp:offline_access"
            };

            foreach (var permission in permissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = demo1Client.Id,
                    Permission = permission
                });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created demo1 client 'mrwho_demo1'");
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
                // Add name claims to admin user for proper display name
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("name", "MrWho Administrator"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("given_name", "MrWho"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("family_name", "Administrator"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("preferred_username", "admin"));
                
                _logger.LogInformation("Created admin user 'admin@mrwho.local' with name claims");
            }
            else
            {
                _logger.LogError("Failed to create admin user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            // Check if existing admin user has name claims, and add them if missing
            var existingClaims = await _userManager.GetClaimsAsync(adminUser);
            var hasNameClaim = existingClaims.Any(c => c.Type == "name");
            var hasGivenNameClaim = existingClaims.Any(c => c.Type == "given_name");
            var hasFamilyNameClaim = existingClaims.Any(c => c.Type == "family_name");
            var hasPreferredUsernameClaim = existingClaims.Any(c => c.Type == "preferred_username");

            if (!hasNameClaim)
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("name", "MrWho Administrator"));
                _logger.LogInformation("Added 'name' claim to existing admin user");
            }

            if (!hasGivenNameClaim)
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("given_name", "MrWho"));
                _logger.LogInformation("Added 'given_name' claim to existing admin user");
            }

            if (!hasFamilyNameClaim)
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("family_name", "Administrator"));
                _logger.LogInformation("Added 'family_name' claim to existing admin user");
            }

            if (!hasPreferredUsernameClaim)
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("preferred_username", "admin"));
                _logger.LogInformation("Added 'preferred_username' claim to existing admin user");
            }
        }

        // 3.5. Create demo1 user if it doesn't exist
        var demo1User = await _userManager.FindByNameAsync("demo1@example.com");
        if (demo1User == null)
        {
            demo1User = new IdentityUser
            {
                UserName = "demo1@example.com",
                Email = "demo1@example.com",
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(demo1User, "Demo123");
            if (result.Succeeded)
            {
                // Add name claims to demo1 user for proper display name
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("name", "Demo User One"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("given_name", "Demo"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("family_name", "User One"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("preferred_username", "demo1"));
                
                _logger.LogInformation("Created demo1 user 'demo1@example.com' with name claims");
            }
            else
            {
                _logger.LogError("Failed to create demo1 user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }

        // Sync the admin client with OpenIddict
        await SyncClientWithOpenIddictAsync(adminClient!);

        // Sync the demo1 client with OpenIddict
        await SyncClientWithOpenIddictAsync(demo1Client!);
        
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
                        descriptor.Permissions.Add("scp:openid");
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
                    case "offline_access":
                        descriptor.Permissions.Add($"scp:{scope.Scope}");
                        break;
                    case "api.read":
                    case "api.write":
                        // For custom API scopes, use the scp: prefix (which is the OpenIddict format for custom scopes)
                        descriptor.Permissions.Add($"scp:{scope.Scope}");
                        break;
                    default:
                        // For other custom scopes, add them with the scp: prefix
                        descriptor.Permissions.Add($"scp:{scope.Scope}");
                        break;
                }
            }

            // IMPORTANT: Also add the endpoint access if we have openid scope 
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
                    !permission.Permission.StartsWith("scp:") &&
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
        var correctApiPermissions = apiScopes.Select(scope => $"scp:{scope}").ToList();

        // Remove old API permissions with incorrect format
        var oldApiPermissions = client.Permissions
            .Where(p => (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) ||
                       p.Permission.StartsWith("oidc:scope:api.") ||
                       p.Permission.Contains("Prefixes.Scope"))
            .ToList();

        // Remove old API permissions
        if (oldApiPermissions.Any())
        {
            _logger.LogInformation("Removing old API permissions with incorrect format for client '{ClientId}': {Permissions}", 
                client.ClientId, string.Join(", ", oldApiPermissions.Select(p => p.Permission)));
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
            _logger.LogInformation("Adding missing correct API permissions for client '{ClientId}': {Permissions}", 
                client.ClientId, string.Join(", ", missingApiPermissions));
            foreach (var permission in missingApiPermissions)
            {
                _context.ClientPermissions.Add(new ClientPermission
                {
                    ClientId = client.Id,
                    Permission = permission
                });
            }
        }

        if (oldApiPermissions.Any() || missingApiPermissions.Any())
        {
            await _context.SaveChangesAsync();
            _logger.LogInformation("Successfully fixed API permissions for client '{ClientId}'", client.ClientId);
        }
    }
}
