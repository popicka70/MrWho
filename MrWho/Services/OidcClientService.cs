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
    private readonly IOpenIddictScopeManager _scopeManager; // added
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<OidcClientService> _logger;

    // Fallback literal permissions for endpoints not exposed as constants in current OpenIddict version
    private const string UserInfoEndpointPermission = "endpoints:userinfo";
    private const string RevocationEndpointPermission = "endpoints:revocation";
    private const string IntrospectionEndpointPermission = "endpoints:introspection";

    public OidcClientService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager, // added
        UserManager<IdentityUser> userManager,
        ILogger<OidcClientService> logger)
    {
        _context = context;
        _applicationManager = applicationManager;
        _scopeManager = scopeManager; // added
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

    // Build application descriptor (Create/Update) without always deleting existing app (Step 3)
    private OpenIddictApplicationDescriptor BuildDescriptor(Client client)
    {
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

        foreach (var permission in client.Permissions.Select(p => p.Permission))
        {
            if (permission.StartsWith("scp:") || permission.StartsWith("oidc:scope:"))
                continue; // skip derived/legacy
            if (!descriptor.Permissions.Contains(permission))
                descriptor.Permissions.Add(permission);
        }

        foreach (var redirect in client.RedirectUris)
            descriptor.RedirectUris.Add(new Uri(redirect.Uri));
        foreach (var postLogout in client.PostLogoutUris)
            descriptor.PostLogoutRedirectUris.Add(new Uri(postLogout.Uri));

        return descriptor;
    }

    /// <summary>
    /// Initialize essential data that must always be present (admin realm, admin client, admin user)
    /// </summary>
    public async Task InitializeEssentialDataAsync()
    {
        // Detect test environment for enabling relaxed flows (password grant) in tests only
        var isTesting = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Testing", StringComparison.OrdinalIgnoreCase);

        // Ensure flag backfill first
        await BackfillEndpointAccessFlagsAsync();

        // Ensure mrwho.use scope exists in OpenIddict (create if missing)
        try
        {
            if (await _scopeManager.FindByNameAsync(StandardScopes.MrWhoUse) == null)
            {
                var scopeDescriptor = new OpenIddictScopeDescriptor
                {
                    Name = StandardScopes.MrWhoUse,
                    DisplayName = "MrWho Admin Usage",
                    Description = "Allows calling protected MrWho administration API endpoints"
                };
                // Associate resource if standard API exists
                scopeDescriptor.Resources.Add("mrwho_api");
                await _scopeManager.CreateAsync(scopeDescriptor);
                _logger.LogInformation("Created OpenIddict scope '{Scope}'", StandardScopes.MrWhoUse);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed ensuring mrwho.use scope");
        }

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

        // Admin client
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
                AllowPasswordFlow = isTesting, // enable password flow ONLY for tests
                AllowRefreshTokenFlow = true,
                RequirePkce = true,
                RequireClientSecret = true,
                CreatedBy = "System",
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = false
            };

            _context.Clients.Add(adminClient);
            await _context.SaveChangesAsync();

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
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = adminClient.Id, Uri = uri });

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
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = adminClient.Id, Uri = uri });

            var scopes = new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite, StandardScopes.MrWhoUse };
            foreach (var scope in scopes)
                _context.ClientScopes.Add(new ClientScope { ClientId = adminClient.Id, Scope = scope });

            var basePermissions = new List<string>
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            };
            if (isTesting)
            {
                // allow password grant ONLY for test tokens
                basePermissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
            }
            foreach (var p in basePermissions)
                _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = p });
            _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = "scp:mrwho.use" });

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created admin client 'mrwho_admin_web' with standardized permissions (PasswordGrant={Password})", isTesting);
        }
        else
        {
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
            // Enable password flow dynamically in test environment if not already enabled
            if (isTesting && !adminClient.AllowPasswordFlow)
            {
                adminClient.AllowPasswordFlow = true;
                adminClient.UpdatedAt = DateTime.UtcNow;
                adminClient.UpdatedBy = "TestSetup";
                await _context.SaveChangesAsync();
                // Explicit permission not required here; SyncClientWithOpenIddictAsync will add it via descriptor
                _logger.LogInformation("Enabled password grant for admin client in test environment");
            }
        }

        // demo1 client
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
                CreatedBy = "System",
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = false
            };
            _context.Clients.Add(demo1Client);
            await _context.SaveChangesAsync();

            foreach (var uri in new[] { "https://localhost:7037/signin-oidc", "https://localhost:7037/callback" })
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = demo1Client.Id, Uri = uri });
            foreach (var uri in new[] { "https://localhost:7037/", "https://localhost:7037/signout-callback-oidc" })
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = demo1Client.Id, Uri = uri });
            foreach (var scope in new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite })
                _context.ClientScopes.Add(new ClientScope { ClientId = demo1Client.Id, Scope = scope });
            foreach (var p in new[] { OpenIddictConstants.Permissions.Endpoints.Authorization, OpenIddictConstants.Permissions.Endpoints.Token, OpenIddictConstants.Permissions.Endpoints.EndSession, OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.GrantTypes.RefreshToken, OpenIddictConstants.Permissions.ResponseTypes.Code })
                _context.ClientPermissions.Add(new ClientPermission { ClientId = demo1Client.Id, Permission = p });
            await _context.SaveChangesAsync();
        }
        else
        {
            var legacy = demo1Client.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) || p.Permission == "scp:openid").ToList();
            if (legacy.Any()) { _context.ClientPermissions.RemoveRange(legacy); await _context.SaveChangesAsync(); }
        }

        // m2m client
        var m2mClient = await _context.Clients
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_demo_api_client");
        if (m2mClient == null)
        {
            m2mClient = new Client
            {
                ClientId = "mrwho_demo_api_client",
                ClientSecret = "DemoApiClientSecret2025!",
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
                AllowAccessToUserInfoEndpoint = false,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = true
            };
            _context.Clients.Add(m2mClient);
            await _context.SaveChangesAsync();
            foreach (var scope in new[] { StandardScopes.ApiRead, StandardScopes.ApiWrite })
                _context.ClientScopes.Add(new ClientScope { ClientId = m2mClient.Id, Scope = scope });
            foreach (var p in new[] { OpenIddictConstants.Permissions.Endpoints.Token, OpenIddictConstants.Permissions.GrantTypes.ClientCredentials })
                _context.ClientPermissions.Add(new ClientPermission { ClientId = m2mClient.Id, Permission = p });
            await _context.SaveChangesAsync();
        }
        else
        {
            var legacy = m2mClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) || p.Permission == "scp:openid").ToList();
            if (legacy.Any()) { _context.ClientPermissions.RemoveRange(legacy); await _context.SaveChangesAsync(); }
        }

        // Users (unchanged)
        var adminUser = await _userManager.FindByNameAsync("admin@mrwho.local");
        if (adminUser == null)
        {
            adminUser = new IdentityUser { UserName = "admin@mrwho.local", Email = "admin@mrwho.local", EmailConfirmed = true };
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
        }
        else
        {
            var adminClaims = await _userManager.GetClaimsAsync(adminUser);
            if (!adminClaims.Any(c => c.Type == "realm"))
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("realm", "admin"));
        }

        var demo1User = await _userManager.FindByNameAsync("demo1@example.com");
        if (demo1User == null)
        {
            demo1User = new IdentityUser { UserName = "demo1@example.com", Email = "demo1@example.com", EmailConfirmed = true };
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
        }
        else
        {
            var demoClaims = await _userManager.GetClaimsAsync(demo1User);
            if (!demoClaims.Any(c => c.Type == "realm"))
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("realm", "demo"));
        }

        if (adminClient != null && adminUser != null && !await _context.ClientUsers.AnyAsync(cu => cu.ClientId == adminClient.Id && cu.UserId == adminUser.Id))
            _context.ClientUsers.Add(new ClientUser { ClientId = adminClient.Id, UserId = adminUser.Id, CreatedAt = DateTime.UtcNow, CreatedBy = "System" });
        if (demo1Client != null && demo1User != null && !await _context.ClientUsers.AnyAsync(cu => cu.ClientId == demo1Client.Id && cu.UserId == demo1User.Id))
            _context.ClientUsers.Add(new ClientUser { ClientId = demo1Client.Id, UserId = demo1User.Id, CreatedAt = DateTime.UtcNow, CreatedBy = "System" });
        await _context.SaveChangesAsync();

        await SyncClientWithOpenIddictAsync(adminClient!);
        await SyncClientWithOpenIddictAsync(demo1Client!);
        await SyncClientWithOpenIddictAsync(m2mClient!);
    }

    public async Task InitializeDefaultRealmAndClientsAsync()
    {
        await BackfillEndpointAccessFlagsAsync();

        var defaultRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "default");
        if (defaultRealm == null)
        {
            defaultRealm = new Realm { Name = "default", DisplayName = "Default Realm", Description = "Default realm for OIDC clients", IsEnabled = true, CreatedBy = "System" };
            _context.Realms.Add(defaultRealm);
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default realm");
        }

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
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = true
            };
            _context.Clients.Add(defaultClient);
            await _context.SaveChangesAsync();

            foreach (var uri in new[] { "https://localhost:7001/callback", "http://localhost:5001/callback", "https://localhost:7002/", "https://localhost:7002/callback", "https://localhost:7002/signin-oidc" })
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = defaultClient.Id, Uri = uri });
            foreach (var uri in new[] { "https://localhost:7001/", "http://localhost:5001/", "https://localhost:7002/", "https://localhost:7002/signout-callback-oidc" })
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = defaultClient.Id, Uri = uri });
            foreach (var scope in new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles })
                _context.ClientScopes.Add(new ClientScope { ClientId = defaultClient.Id, Scope = scope });

            // Only grant/endpoint permissions; no scope-derived stored perms
            foreach (var permission in new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            })
                _context.ClientPermissions.Add(new ClientPermission { ClientId = defaultClient.Id, Permission = permission });

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default client 'postman_client'");
        }
        else
        {
            // Remove legacy stored scope permissions in default client
            var legacy = defaultClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || p.Permission == "scp:openid" || p.Permission.StartsWith("scp:email") || p.Permission.StartsWith("scp:profile") || p.Permission.StartsWith("scp:roles") ).ToList();
            if (legacy.Any())
            {
                _context.ClientPermissions.RemoveRange(legacy);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Cleaned {Count} legacy scope permissions from default client", legacy.Count);
            }
        }

        var enabledClients = await GetEnabledClientsAsync();
        foreach (var client in enabledClients)
            await SyncClientWithOpenIddictAsync(client);
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
            var descriptor = BuildDescriptor(client);

            if (existingClient == null)
            {
                await _applicationManager.CreateAsync(descriptor);
                _logger.LogInformation("Created OpenIddict application for '{ClientId}'", client.ClientId);
            }
            else
            {
                await _applicationManager.UpdateAsync(existingClient, descriptor);
                _logger.LogInformation("Updated OpenIddict application for '{ClientId}'", client.ClientId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync client '{ClientId}'", client.ClientId);
            throw;
        }
    }
}
