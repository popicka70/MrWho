using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using OpenIddict.Abstractions;

namespace MrWho.Services;

public class OidcClientService : IOidcClientService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<OidcClientService> _logger;

    // Fallback literal permissions for endpoints not exposed as constants in current OpenIddict version
    private const string UserInfoEndpointPermission = "endpoints:userinfo";
    private const string RevocationEndpointPermission = "endpoints:revocation";
    private const string IntrospectionEndpointPermission = "endpoints:introspection";

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

    private async Task BackfillEndpointAccessFlagsAsync()
    {
        try
        {
            var clients = await _context.Clients.Where(c =>
                c.AllowAccessToUserInfoEndpoint == null ||
                c.AllowAccessToRevocationEndpoint == null ||
                c.AllowAccessToIntrospectionEndpoint == null).ToListAsync();
            if (clients.Count == 0) return;
            int updated = 0;
            foreach (var c in clients)
            {
                var isMachine = c.ClientType == ClientType.Machine || (c.AllowClientCredentialsFlow && !c.AllowAuthorizationCodeFlow && !c.AllowPasswordFlow);
                if (c.AllowAccessToUserInfoEndpoint == null)
                    c.AllowAccessToUserInfoEndpoint = !isMachine; // interactive clients get userinfo
                if (c.AllowAccessToRevocationEndpoint == null)
                    c.AllowAccessToRevocationEndpoint = true; // generally safe
                if (c.AllowAccessToIntrospectionEndpoint == null)
                    c.AllowAccessToIntrospectionEndpoint = isMachine; // machines often need introspection
                c.UpdatedAt = DateTime.UtcNow;
                c.UpdatedBy ??= "Backfill";
                updated++;
            }
            if (updated > 0)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Backfilled endpoint access flags for {Count} clients", updated);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error backfilling endpoint access flags");
        }
    }

    // Centralized scope->permission mapping (Step 1 standardization) - unify ALL scopes to scp: prefix
    private static (bool hasOpenId, List<string> permissions) BuildScopePermissions(IEnumerable<string> scopes)
    {
        var perms = new List<string>();
        var hasOpenId = false;
        foreach (var scope in scopes.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.Equals(scope, StandardScopes.OpenId, StringComparison.OrdinalIgnoreCase))
            {
                perms.Add("scp:openid");
                hasOpenId = true;
            }
            else
            {
                perms.Add($"scp:{scope}");
            }
        }
        return (hasOpenId, perms);
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
                CreatedBy = "System",
                DefaultThemeName = "corporate"
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
                CreatedBy = "System",
                DefaultThemeName = "ocean"
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
                CreatedBy = "System",
                // Endpoint access defaults (interactive web app)
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = false
            };

            _context.Clients.Add(adminClient);
            await _context.SaveChangesAsync();

            // Add redirect URIs for MrWhoAdmin.Web (local https 7257, docker host http 8081, and hosted onrender)
            var redirectUris = new[]
            {
                "https://localhost:7257/signin-oidc",
                "https://localhost:7257/callback",
                "http://localhost:8081/signin-oidc",
                "http://localhost:8081/callback",
                "https://mrwho.onrender.com/signin-oidc",
                "https://mrwho.onrender.com/callback",
                "https://mrwhoadmin.onrender.com/signin-oidc",
                "https://mrwhoadmin.onrender.com/callback"
            };

            foreach (var uri in redirectUris)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = adminClient.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs (local https 7257, docker host http 8081, and hosted onrender)
            var postLogoutUris = new[]
            {
                "https://localhost:7257/",
                "https://localhost:7257/signout-callback-oidc",
                "http://localhost:8081/",
                "http://localhost:8081/signout-callback-oidc",
                "https://mrwho.onrender.com/",
                "https://mrwho.onrender.com/signout-callback-oidc",
                "https://mrwhoadmin.onrender.com/",
                "https://mrwhoadmin.onrender.com/signout-callback-oidc"
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
            var scopes = new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite, StandardScopes.MrWhoUse };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = adminClient.Id,
                    Scope = scope
                });
            }

            // Standardized: only custom scopes stored in permissions beyond endpoint/grant constants; openid etc. handled via scopes => permissions during sync
            var basePermissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            };
            foreach (var p in basePermissions)
                _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = p });
            // Custom scope mrwho.use explicit permission (scp: format)
            _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = "scp:mrwho.use" });

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created admin client 'mrwho_admin_web' with standardized permissions");
        }
        else
        {
            // Cleanup legacy permission formats for admin client
            var legacy = adminClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) || p.Permission == "scp:openid").ToList();
            if (legacy.Any())
            {
                _context.ClientPermissions.RemoveRange(legacy);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Removed {Count} legacy permissions from admin client", legacy.Count);
            }
            if (!adminClient.Permissions.Any(p => p.Permission == "scp:mrwho.use"))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = "scp:mrwho.use" });
                await _context.SaveChangesAsync();
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
                RealmId = (await _context.Realms.FirstAsync(r => r.Name == "demo")).Id,
                IsEnabled = true,
                ClientType = ClientType.Confidential,
                AllowAuthorizationCodeFlow = true,
                AllowClientCredentialsFlow = false,
                AllowPasswordFlow = false,
                AllowRefreshTokenFlow = true,
                RequirePkce = true,
                RequireClientSecret = true,
                CreatedBy = "System",
                // Endpoint access defaults
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = false
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

            // Add scopes for demo1 (include API scopes)
            var scopes = new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = demo1Client.Id,
                    Scope = scope
                });
            }

            // Add permissions for demo1 (include API scope permissions)
            var permissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                "scp:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                "scp:offline_access",
                "scp:api.read",
                "scp:api.write"
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
            _logger.LogInformation("Created demo1 client 'mrwho_demo1' with API scopes");
        }
        else
        {
            // Ensure required redirects/post-logout URIs, scopes, and permissions exist for existing demo1 client
            var requiredRedirects = new[]
            {
                "https://localhost:7037/signin-oidc",
                "https://localhost:7037/callback"
            };
            var requiredPostLogout = new[]
            {
                "https://localhost:7037/",
                "https://localhost:7037/signout-callback-oidc"
            };
            var requiredScopes = new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite };
            var requiredPermissions = new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                "scp:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                "scp:offline_access",
                "scp:api.read",
                "scp:api.write"
            };

            var added = false;

            var missingRedirects = requiredRedirects.Where(u => !demo1Client.RedirectUris.Any(r => r.Uri == u)).ToList();
            foreach (var uri in missingRedirects)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = demo1Client.Id, Uri = uri });
                added = true;
            }

            var missingPostLogout = requiredPostLogout.Where(u => !demo1Client.PostLogoutUris.Any(r => r.Uri == u)).ToList();
            foreach (var uri in missingPostLogout)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = demo1Client.Id, Uri = uri });
                added = true;
            }

            var missingScopes = requiredScopes.Where(s => !demo1Client.Scopes.Any(cs => cs.Scope == s)).ToList();
            foreach (var s in missingScopes)
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = demo1Client.Id, Scope = s });
                added = true;
            }

            var existingPerms = demo1Client.Permissions.Select(p => p.Permission).ToHashSet();
            foreach (var p in requiredPermissions)
            {
                if (!existingPerms.Contains(p))
                {
                    _context.ClientPermissions.Add(new ClientPermission { ClientId = demo1Client.Id, Permission = p });
                    added = true;
                }
            }

            if (added)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated existing demo1 client with missing URIs/scopes/permissions (API scopes included)");

                // Reload the client
                demo1Client = await _context.Clients
                    .Include(c => c.RedirectUris)
                    .Include(c => c.PostLogoutUris)
                    .Include(c => c.Scopes)
                    .Include(c => c.Permissions)
                    .FirstOrDefaultAsync(c => c.ClientId == "mrwho_demo1");
            }
        }

        // 2.6. Create machine-to-machine client for service-to-service calls if it doesn't exist
        var m2mClient = await _context.Clients
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_demo_api_client");

        if (m2mClient == null)
        {
            // reuse existing demoRealm variable (guaranteed created above)
            m2mClient = new Client
            {
                ClientId = "mrwho_demo_api_client",
                ClientSecret = "DemoApiClientSecret2025!", // demo-only secret
                Name = "MrWho Demo API Machine Client",
                Description = "Machine-to-machine client (client_credentials) for calling MrWhoDemoApi",
                RealmId = demoRealm.Id,
                IsEnabled = true,
                ClientType = ClientType.Machine,
                AllowAuthorizationCodeFlow = false,
                AllowClientCredentialsFlow = true,
                AllowPasswordFlow = false,
                AllowRefreshTokenFlow = false,
                RequirePkce = false,
                RequireClientSecret = true,
                CreatedBy = "System",
                // Endpoint access defaults for M2M (no userinfo, no revocation unless needed)
                AllowAccessToUserInfoEndpoint = false,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = true
            };
            _context.Clients.Add(m2mClient);
            await _context.SaveChangesAsync();

            foreach (var scopeName in new[] { StandardScopes.ApiRead, StandardScopes.ApiWrite })
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = m2mClient.Id, Scope = scopeName });
            }
            foreach (var permission in new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
            })
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = m2mClient.Id, Permission = permission });
            }
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created machine-to-machine client 'mrwho_demo_api_client'.");
        }
        else
        {
            var legacy = m2mClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) || p.Permission == "scp:openid").ToList();
            if (legacy.Any()) { _context.ClientPermissions.RemoveRange(legacy); await _context.SaveChangesAsync(); }
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
            var result = await _userManager.CreateAsync(adminUser, "Adm1n#2025!G7x");
            if (result.Succeeded)
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("name", "MrWho Administrator"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("given_name", "MrWho"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("family_name", "Administrator"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("preferred_username", "admin"));
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("realm", "admin"));
                _logger.LogInformation("Created admin user 'admin@mrwho.local'");
            }
            else
            {
                _logger.LogError("Failed to create admin user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            var adminClaims = await _userManager.GetClaimsAsync(adminUser);
            if (!adminClaims.Any(c => c.Type == "realm"))
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("realm", "admin"));
            }
        }

        // 3.5 Create demo1 user if it doesn't exist
        var demo1User = await _userManager.FindByNameAsync("demo1@example.com");
        if (demo1User == null)
        {
            demo1User = new IdentityUser
            {
                UserName = "demo1@example.com",
                Email = "demo1@example.com",
                EmailConfirmed = true
            };
            var result = await _userManager.CreateAsync(demo1User, "Dem0!User#2025");
            if (result.Succeeded)
            {
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("name", "Demo User One"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("given_name", "Demo"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("family_name", "User One"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("preferred_username", "demo1"));
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("realm", "demo"));
                _logger.LogInformation("Created demo1 user 'demo1@example.com'");
            }
            else
            {
                _logger.LogError("Failed to create demo1 user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            var demoClaims = await _userManager.GetClaimsAsync(demo1User);
            if (!demoClaims.Any(c => c.Type == "realm"))
            {
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("realm", "demo"));
            }
        }

        // Assign users to their clients
        if (adminClient != null && adminUser != null && !await _context.ClientUsers.AnyAsync(cu => cu.ClientId == adminClient.Id && cu.UserId == adminUser.Id))
        {
            _context.ClientUsers.Add(new ClientUser { ClientId = adminClient.Id, UserId = adminUser.Id, CreatedAt = DateTime.UtcNow, CreatedBy = "System" });
        }
        if (demo1Client != null && demo1User != null && !await _context.ClientUsers.AnyAsync(cu => cu.ClientId == demo1Client.Id && cu.UserId == demo1User.Id))
        {
            _context.ClientUsers.Add(new ClientUser { ClientId = demo1Client.Id, UserId = demo1User.Id, CreatedAt = DateTime.UtcNow, CreatedBy = "System" });
        }
        await _context.SaveChangesAsync();

        // Sync clients with OpenIddict
        await SyncClientWithOpenIddictAsync(adminClient!);
        await SyncClientWithOpenIddictAsync(demo1Client!);
        await SyncClientWithOpenIddictAsync(m2mClient!);
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
                CreatedBy = "System",
                // Endpoint defaults for test client
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = true
            };

            _context.Clients.Add(defaultClient);
            await _context.SaveChangesAsync();

            // Add redirect URIs
            foreach (var uri in new[]
            {
                "https://localhost:7001/callback",
                "http://localhost:5001/callback",
                "https://localhost:7002/",
                "https://localhost:7002/callback",
                "https://localhost:7002/signin-oidc"
            })
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri
                {
                    ClientId = defaultClient.Id,
                    Uri = uri
                });
            }

            // Add post-logout URIs
            foreach (var uri in new[]
            {
                "https://localhost:7001/",
                "http://localhost:5001/",
                "https://localhost:7002/",
                "https://localhost:7002/signout-callback-oidc"
            })
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                {
                    ClientId = defaultClient.Id,
                    Uri = uri
                });
            }

            // Add scopes
            foreach (var scope in new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles })
            {
                _context.ClientScopes.Add(new ClientScope
                {
                    ClientId = defaultClient.Id,
                    Scope = scope
                });
            }

            // Add permissions
            foreach (var permission in new[]
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
            })
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
            if ((client.ClientType == ClientType.Confidential || client.ClientType == ClientType.Machine) && client.RequireClientSecret && string.IsNullOrWhiteSpace(client.ClientSecret))
            {
                _logger.LogWarning("Skipping OpenIddict sync for client '{ClientId}': missing secret.", client.ClientId);
                return;
            }

            var existingClient = await _applicationManager.FindByClientIdAsync(client.ClientId);
            if (existingClient != null)
                await _applicationManager.DeleteAsync(existingClient);

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = client.ClientId,
                ClientSecret = client.ClientSecret,
                DisplayName = client.Name,
                ClientType = client.ClientType == ClientType.Public ? OpenIddictConstants.ClientTypes.Public : OpenIddictConstants.ClientTypes.Confidential
            };

            if (client.AllowAuthorizationCodeFlow)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
            }
            if (client.AllowClientCredentialsFlow)
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            if (client.AllowPasswordFlow)
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
            if (client.AllowRefreshTokenFlow)
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

            var (hasOpenId, scopePerms) = BuildScopePermissions(client.Scopes.Select(s => s.Scope));
            foreach (var p in scopePerms) descriptor.Permissions.Add(p);

            if (hasOpenId)
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);

            if (client.AllowAccessToUserInfoEndpoint == true && hasOpenId)
                descriptor.Permissions.Add(UserInfoEndpointPermission);
            if (client.AllowAccessToRevocationEndpoint == true)
                descriptor.Permissions.Add(RevocationEndpointPermission);
            if (client.AllowAccessToIntrospectionEndpoint == true)
                descriptor.Permissions.Add(IntrospectionEndpointPermission);

            // Additional stored permissions (exclude scope-derived and standard endpoint ones already added)
            foreach (var permission in client.Permissions.Select(p => p.Permission))
            {
                if (permission.StartsWith("scp:") || permission.StartsWith("oidc:scope:"))
                    continue; // derived or legacy (already cleaned up)
                if (descriptor.Permissions.Contains(permission))
                    continue;
                descriptor.Permissions.Add(permission);
            }

            foreach (var redirect in client.RedirectUris)
                descriptor.RedirectUris.Add(new Uri(redirect.Uri));
            foreach (var postLogout in client.PostLogoutUris)
                descriptor.PostLogoutRedirectUris.Add(new Uri(postLogout.Uri));

            await _applicationManager.CreateAsync(descriptor);
            _logger.LogInformation("Synced client '{ClientId}' with permissions: {Permissions}", client.ClientId, string.Join(", ", descriptor.Permissions));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync client '{ClientId}'", client.ClientId);
            throw;
        }
    }
}
