using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Models;
using MrWho.Options;
using MrWho.Shared;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace MrWho.Services;

public partial class OidcClientService : IOidcClientService
{
    private readonly ApplicationDbContext _context;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<OidcClientService> _logger;
    private readonly IOptions<OidcClientsOptions> _clientOptions;
    private readonly IClientSecretService? _clientSecretService; // optional (tests may not register)

    // Fallback literal permissions for endpoints not exposed as constants in current OpenIddict version
    private const string UserInfoEndpointPermission = "endpoints.userinfo"; // correct form
    private const string RevocationEndpointPermission = "endpoints.revocation"; // correct form
    private const string IntrospectionEndpointPermission = "endpoints.introspection"; // correct form

    // Back-compat overload for tests and legacy callers without options
    public OidcClientService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<IdentityUser> userManager,
        ILogger<OidcClientService> logger)
        : this(context, applicationManager, scopeManager, userManager, logger, Microsoft.Extensions.Options.Options.Create(new OidcClientsOptions()), null)
    { }

    public OidcClientService(
        ApplicationDbContext context,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        UserManager<IdentityUser> userManager,
        ILogger<OidcClientService> logger,
        IOptions<OidcClientsOptions> clientOptions,
        IClientSecretService? clientSecretService = null)
    {
        _context = context;
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _userManager = userManager;
        _logger = logger;
        _clientOptions = clientOptions;
        _clientSecretService = clientSecretService; // may be null in some test contexts
    }

    private async Task BackfillEndpointAccessFlagsAsync()
    {
        try
        {
            var clients = await _context.Clients.Where(c =>
                c.AllowAccessToUserInfoEndpoint == null ||
                c.AllowAccessToRevocationEndpoint == null ||
                c.AllowAccessToIntrospectionEndpoint == null).ToListAsync();
            if (clients.Count > 0)
            {
                int updated = 0;
                foreach (var c in clients)
                {
                    var isMachine = c.ClientType == ClientType.Machine || (c.AllowClientCredentialsFlow && !c.AllowAuthorizationCodeFlow && !c.AllowPasswordFlow);
                    if (c.AllowAccessToUserInfoEndpoint == null)
                    {
                        c.AllowAccessToUserInfoEndpoint = !isMachine;
                    }

                    if (c.AllowAccessToRevocationEndpoint == null)
                    {
                        c.AllowAccessToRevocationEndpoint = true;
                    }

                    if (c.AllowAccessToIntrospectionEndpoint == null)
                    {
                        c.AllowAccessToIntrospectionEndpoint = isMachine;
                    }

                    c.UpdatedAt = DateTime.UtcNow;
                    c.UpdatedBy ??= "Backfill";
                    updated++;
                }
                await _context.SaveChangesAsync();
                _logger.LogInformation("Backfilled endpoint access flags for {Count} clients", updated);
            }

            // Remove legacy incorrect stored permissions (colon or slash forms)
            var legacyPerms = await _context.ClientPermissions
                .Where(p => p.Permission == "endpoints:userinfo" ||
                            p.Permission == "endpoints:revocation" ||
                            p.Permission == "endpoints:introspection" ||
                            p.Permission == "endpoints/userinfo" ||
                            p.Permission == "endpoints/revocation" ||
                            p.Permission == "endpoints/introspection")
                .ToListAsync();
            if (legacyPerms.Count > 0)
            {
                _context.ClientPermissions.RemoveRange(legacyPerms);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Removed {Count} legacy endpoint permission strings (colon/slash forms)", legacyPerms.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error backfilling endpoint access flags");
        }
    }

    private async Task BackfillClientSecretHistoriesAsync()
    {
        if (_clientSecretService == null)
        {
            return; // not available in some minimal test setups
        }

        try
        {
            var confidentials = await _context.Clients
                .Where(c => (c.ClientType == ClientType.Confidential || c.ClientType == ClientType.Machine)
                            && c.RequireClientSecret
                            && (c.ClientSecret != null)) // has some value (may be placeholder or real)
                .Select(c => new { c.Id, c.ClientId, c.ClientSecret })
                .ToListAsync();

            int created = 0;
            foreach (var c in confidentials)
            {
                bool hasHistory = await _context.ClientSecretHistories.AnyAsync(h => h.ClientId == c.Id && h.Status == ClientSecretStatus.Active && (h.ExpiresAt == null || h.ExpiresAt > DateTime.UtcNow));
                if (hasHistory)
                {
                    continue;
                }

                // If we only have placeholder {HASHED} we cannot recover plaintext -> require manual rotation later.
                if (string.Equals(c.ClientSecret, "{HASHED}", StringComparison.Ordinal))
                {
                    _logger.LogDebug("Skipping secret history backfill for {ClientId}: placeholder only; rotate manually", c.ClientId);
                    continue;
                }

                try
                {
                    await _clientSecretService.SetNewSecretAsync(c.Id, providedPlaintext: c.ClientSecret, markOldAsRetired: false);
                    created++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed backfilling secret history for client {ClientId}", c.ClientId);
                }
            }
            if (created > 0)
            {
                _logger.LogInformation("Backfilled secret history for {Count} clients", created);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during client secret history backfill");
        }
    }

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

        // Re-enable advertising PAR endpoint (permission only) so clients can push requests.
        if (client.ParMode is PushedAuthorizationMode.Enabled or PushedAuthorizationMode.Required)
        {
            if (!descriptor.Permissions.Contains(OpenIddictConstants.Permissions.Endpoints.PushedAuthorization))
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
        }
        // Intentionally DO NOT add requirement feature to avoid forcing request_uri on every authorize request.

        // Per-application PKCE requirement
        if (client.RequirePkce)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

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
            if (permission.StartsWith("scp:") || permission.StartsWith("oidc:scope:")) continue;
            if (permission is "endpoints:userinfo" or "endpoints:revocation" or "endpoints:introspection" ||
                permission is "endpoints/userinfo" or "endpoints/revocation" or "endpoints/introspection") continue;
            if (!descriptor.Permissions.Contains(permission)) descriptor.Permissions.Add(permission);
        }
        foreach (var redirect in client.RedirectUris) descriptor.RedirectUris.Add(new Uri(redirect.Uri));
        foreach (var postLogout in client.PostLogoutUris) descriptor.PostLogoutRedirectUris.Add(new Uri(postLogout.Uri));
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

        // Ensure mrwho.use scope exists first
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

        // NEW: ensure mrwho.metrics scope exists for M2M metrics access
        try
        {
            const string metricsScope = "mrwho.metrics";
            if (await _scopeManager.FindByNameAsync(metricsScope) == null)
            {
                var scopeDescriptor = new OpenIddictScopeDescriptor
                {
                    Name = metricsScope,
                    DisplayName = "MrWho Metrics Access",
                    Description = "Allows reading protocol metrics endpoints"
                };
                scopeDescriptor.Resources.Add("mrwho_api");
                await _scopeManager.CreateAsync(scopeDescriptor);
                _logger.LogInformation("Created OpenIddict scope '{Scope}'", metricsScope);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed ensuring mrwho.metrics scope");
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

        // Load configured URIs for admin client strictly from options (no hardcoded defaults)
        var cfgAdmin = _clientOptions.Value.Admin ?? new OidcClientsOptions.ClientOptions();
        if (string.IsNullOrWhiteSpace(cfgAdmin.ClientId))
        {
            cfgAdmin.ClientId = "mrwho_admin_web";
        }

        var adminConfiguredRedirects = (IEnumerable<string>)(cfgAdmin.RedirectUris ?? Array.Empty<string>());
        var adminConfiguredPostLogout = (IEnumerable<string>)(cfgAdmin.PostLogoutRedirectUris ?? Array.Empty<string>());

        if (adminClient == null)
        {
            adminClient = new Client
            {
                ClientId = cfgAdmin.ClientId!,
                ClientSecret = string.IsNullOrWhiteSpace(cfgAdmin.ClientSecret) ? "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY" : cfgAdmin.ClientSecret, // allow override via config
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
                AllowAccessToIntrospectionEndpoint = false,
                // Enable PAR for admin web by default so the OIDC client can use PAR
                ParMode = PushedAuthorizationMode.Enabled,
                JarMode = JarMode.Optional // enable JAR for admin client
            };

            _context.Clients.Add(adminClient);
            await _context.SaveChangesAsync();

            foreach (var uri in adminConfiguredRedirects)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = adminClient.Id, Uri = uri });
            }

            foreach (var uri in adminConfiguredPostLogout)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = adminClient.Id, Uri = uri });
            }

            // NOTE: Intentionally NOT seeding offline_access for admin web to avoid refresh tokens + MFA on first login
            var scopes = new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.ApiRead, StandardScopes.ApiWrite, StandardScopes.MrWhoUse, StandardScopes.MrWhoMetrics };
            foreach (var scope in scopes)
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = adminClient.Id, Scope = scope });
            }

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
                basePermissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
            }
            foreach (var p in basePermissions)
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = p });
            }

            _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = $"scp:{StandardScopes.MrWhoUse}" });
            _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = $"scp:{StandardScopes.MrWhoMetrics}" });

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created admin client '{ClientId}' without offline_access scope", adminClient.ClientId);
        }
        else
        {
            var legacy = adminClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.")) && !p.Permission.StartsWith("scp:") || p.Permission == "scp:openid").ToList();
            if (legacy.Any())
            {
                _context.ClientPermissions.RemoveRange(legacy);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Removed {Count} legacy permissions from admin client", legacy.Count);
            }
            if (!adminClient.Permissions.Any(p => p.Permission == $"scp:{StandardScopes.MrWhoUse}"))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = $"scp:{StandardScopes.MrWhoUse}" });
                await _context.SaveChangesAsync();
            }
            if (!adminClient.Scopes.Any(s => s.Scope == StandardScopes.MrWhoMetrics))
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = adminClient.Id, Scope = StandardScopes.MrWhoMetrics });
                await _context.SaveChangesAsync();
                _logger.LogInformation("Added scope {Scope} to admin client", StandardScopes.MrWhoMetrics);
            }
            if (!adminClient.Permissions.Any(p => p.Permission == $"scp:{StandardScopes.MrWhoMetrics}"))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = adminClient.Id, Permission = $"scp:{StandardScopes.MrWhoMetrics}" });
                await _context.SaveChangesAsync();
            }
            if (adminClient.ParMode == null)
            {
                adminClient.ParMode = PushedAuthorizationMode.Enabled;
                adminClient.UpdatedAt = DateTime.UtcNow;
                adminClient.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
                _logger.LogInformation("Backfilled ParMode=Enabled for admin client");
            }
            if (adminClient.JarMode == null)
            {
                adminClient.JarMode = JarMode.Optional; // backfill JAR support
                adminClient.UpdatedAt = DateTime.UtcNow;
                adminClient.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
                _logger.LogInformation("Backfilled JarMode=Optional for admin client");
            }

            // Ensure configured redirect/post-logout URIs exist
            var existingRedirects = adminClient.RedirectUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in adminConfiguredRedirects)
            {
                if (!existingRedirects.Contains(uri))
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = adminClient.Id, Uri = uri });
                    _logger.LogInformation("Added admin redirect URI: {Uri}", uri);
                }
            }
            var existingPostLogout = adminClient.PostLogoutUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in adminConfiguredPostLogout)
            {
                if (!existingPostLogout.Contains(uri))
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = adminClient.Id, Uri = uri });
                    _logger.LogInformation("Added admin post-logout URI: {Uri}", uri);
                }
            }
            await _context.SaveChangesAsync();

            // NEW: remove offline_access scope from admin client if present
            var offlineScopes = await _context.ClientScopes
                .Where(s => s.ClientId == adminClient.Id && s.Scope == StandardScopes.OfflineAccess)
                .ToListAsync();
            if (offlineScopes.Count > 0)
            {
                _context.ClientScopes.RemoveRange(offlineScopes);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Removed offline_access scope from admin client");
            }

            // Enable password grant in tests only
            if (isTesting && !adminClient.AllowPasswordFlow)
            {
                adminClient.AllowPasswordFlow = true;
                adminClient.UpdatedAt = DateTime.UtcNow;
                adminClient.UpdatedBy = "TestSetup";
                await _context.SaveChangesAsync();
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

        var cfgDemo1 = _clientOptions.Value.Demo1 ?? new OidcClientsOptions.ClientOptions();
        if (string.IsNullOrWhiteSpace(cfgDemo1.ClientId))
        {
            cfgDemo1.ClientId = "mrwho_demo1";
        }

        var demo1ConfiguredRedirects = (IEnumerable<string>)(cfgDemo1.RedirectUris ?? Array.Empty<string>());
        var demo1ConfiguredPostLogout = (IEnumerable<string>)(cfgDemo1.PostLogoutRedirectUris ?? Array.Empty<string>());

        const string Demo1LongSecret = "PyfrZln6d2ifAbdL_2gr316CERUMyzfpgmxJ1J3xJsWUnfHGakcvjWenB_OwQqnv";

        if (demo1Client == null)
        {
            demo1Client = new Client
            {
                ClientId = cfgDemo1.ClientId!,
                ClientSecret = string.IsNullOrWhiteSpace(cfgDemo1.ClientSecret) ? Demo1LongSecret : cfgDemo1.ClientSecret,
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
                AllowAccessToIntrospectionEndpoint = true,
                ParMode = PushedAuthorizationMode.Enabled,
                JarMode = JarMode.Optional // enable JAR for demo client used in tests
            };
            _context.Clients.Add(demo1Client);
            await _context.SaveChangesAsync();

            foreach (var uri in demo1ConfiguredRedirects)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = demo1Client.Id, Uri = uri });
            }
            // EXTRA: include NuGet demo app redirects
            foreach (var uri in new[] { "https://localhost:64820/signin-oidc", "https://localhost:64820/callback" })
            {
                if (!demo1ConfiguredRedirects.Contains(uri, StringComparer.OrdinalIgnoreCase))
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = demo1Client.Id, Uri = uri });
                }
            }

            foreach (var uri in demo1ConfiguredPostLogout)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = demo1Client.Id, Uri = uri });
            }
            // EXTRA: include NuGet demo app post-logout redirects
            foreach (var uri in new[] { "https://localhost:64820/", "https://localhost:64820/signout-callback-oidc" })
            {
                if (!demo1ConfiguredPostLogout.Contains(uri, StringComparer.OrdinalIgnoreCase))
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = demo1Client.Id, Uri = uri });
                }
            }

            foreach (var scope in new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite })
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = demo1Client.Id, Scope = scope });
            }

            foreach (var p in new[] { OpenIddictConstants.Permissions.Endpoints.Authorization, OpenIddictConstants.Permissions.Endpoints.Token, OpenIddictConstants.Permissions.Endpoints.EndSession, OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.GrantTypes.RefreshToken, OpenIddictConstants.Permissions.ResponseTypes.Code })
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = demo1Client.Id, Permission = p });
            }

            await _context.SaveChangesAsync();
        }
        else
        {
            var legacy = demo1Client.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) || p.Permission == "scp:openid").ToList();
            if (legacy.Any()) { _context.ClientPermissions.RemoveRange(legacy); await _context.SaveChangesAsync(); }
            // Backfill ParMode for demo1 if missing
            if (demo1Client.ParMode == null)
            {
                demo1Client.ParMode = PushedAuthorizationMode.Enabled;
                demo1Client.UpdatedAt = DateTime.UtcNow;
                demo1Client.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
            }
            if (demo1Client.JarMode == null)
            {
                demo1Client.JarMode = JarMode.Optional;
                demo1Client.UpdatedAt = DateTime.UtcNow;
                demo1Client.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
            }

            // Backfill: ensure client secret is long enough for HS256 request object signatures
            if (string.IsNullOrWhiteSpace(demo1Client.ClientSecret) || demo1Client.ClientSecret.Length < 32)
            {
                demo1Client.ClientSecret = string.IsNullOrWhiteSpace(cfgDemo1.ClientSecret) ? Demo1LongSecret : cfgDemo1.ClientSecret;
                demo1Client.UpdatedAt = DateTime.UtcNow;
                demo1Client.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated demo1 client secret to meet HS256 length requirements");
            }

            // Ensure configured redirect/post-logout URIs exist
            var existingDemo1Redirects = demo1Client.RedirectUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in demo1ConfiguredRedirects)
            {
                if (!existingDemo1Redirects.Contains(uri))
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = demo1Client.Id, Uri = uri });
                    _logger.LogInformation("Added demo1 redirect URI: {Uri}", uri);
                }
            }
            // EXTRA: NuGet demo app redirects
            foreach (var uri in new[] { "https://localhost:64820/signin-oidc", "https://localhost:64820/callback" })
            {
                if (!existingDemo1Redirects.Contains(uri))
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = demo1Client.Id, Uri = uri });
                    _logger.LogInformation("Added demo1 (NuGet) redirect URI: {Uri}", uri);
                }
            }
            var existingDemo1PostLogout = demo1Client.PostLogoutUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in demo1ConfiguredPostLogout)
            {
                if (!existingDemo1PostLogout.Contains(uri))
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = demo1Client.Id, Uri = uri });
                    _logger.LogInformation("Added demo1 post-logout URI: {Uri}", uri);
                }
            }
            // EXTRA: NuGet demo app post logout URIs
            foreach (var uri in new[] { "https://localhost:64820/", "https://localhost:64820/signout-callback-oidc" })
            {
                if (!existingDemo1PostLogout.Contains(uri))
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = demo1Client.Id, Uri = uri });
                    _logger.LogInformation("Added demo1 (NuGet) post-logout URI: {Uri}", uri);
                }
            }
            await _context.SaveChangesAsync();
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
                ClientId = _clientOptions.Value.M2M?.ClientId ?? "mrwho_demo_api_client",
                ClientSecret = _clientOptions.Value.M2M?.ClientSecret ?? "DemoApiClientSecret2025!",
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
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = m2mClient.Id, Scope = scope });
            }

            foreach (var p in new[] { OpenIddictConstants.Permissions.Endpoints.Token, OpenIddictConstants.Permissions.GrantTypes.ClientCredentials })
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = m2mClient.Id, Permission = p });
            }

            await _context.SaveChangesAsync();
        }
        else
        {
            var legacy = m2mClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")) || p.Permission == "scp:openid").ToList();
            if (legacy.Any()) { _context.ClientPermissions.RemoveRange(legacy); await _context.SaveChangesAsync(); }
        }

        // Users (admin) - add metrics.read role claim
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
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("roles", "metrics.read"));
                _logger.LogInformation("Created admin user and granted metrics.read role claim");
            }
        }
        else
        {
            var adminClaims = await _userManager.GetClaimsAsync(adminUser);
            if (!adminClaims.Any(c => c.Type == "realm"))
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("realm", "admin"));
            }
            if (!adminClaims.Any(c => c.Type == "roles" && string.Equals(c.Value, "metrics.read", StringComparison.OrdinalIgnoreCase)))
            {
                await _userManager.AddClaimAsync(adminUser, new System.Security.Claims.Claim("roles", "metrics.read"));
                _logger.LogInformation("Granted metrics.read role claim to admin user");
            }
        }

        // demo1 user
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
            {
                await _userManager.AddClaimAsync(demo1User, new System.Security.Claims.Claim("realm", "demo"));
            }
        }

        if (adminClient != null && adminUser != null && !await _context.ClientUsers.AnyAsync(cu => cu.ClientId == adminClient.Id && cu.UserId == adminUser.Id))
        {
            _context.ClientUsers.Add(new ClientUser { ClientId = adminClient.Id, UserId = adminUser.Id, CreatedAt = DateTime.UtcNow, CreatedBy = "System" });
        }

        await _context.SaveChangesAsync();

        // NEW: backfill secret histories before syncing with OpenIddict so plaintext (encrypted) is available
        await BackfillClientSecretHistoriesAsync();

        await SyncClientWithOpenIddictAsync(adminClient!);
        await SyncClientWithOpenIddictAsync(m2mClient!);

        // Standard service M2M (mrwho_m2m)
        var serviceM2M = await _context.Clients
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_m2m");
        if (serviceM2M == null)
        {
            serviceM2M = new Client
            {
                ClientId = _clientOptions.Value.ServiceM2M?.ClientId ?? "mrwho_m2m",
                ClientSecret = _clientOptions.Value.ServiceM2M?.ClientSecret ?? "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
                Name = "MrWho Service M2M Client",
                Description = "Standard machine client (client_credentials) for calling protected MrWho API endpoints requiring mrwho.use",
                RealmId = adminRealm.Id,
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
            _context.Clients.Add(serviceM2M);
            await _context.SaveChangesAsync();

            // Required scopes for tests/integration: mrwho.use + api.read + mrwho.metrics
            _context.ClientScopes.Add(new ClientScope { ClientId = serviceM2M.Id, Scope = StandardScopes.MrWhoUse });
            _context.ClientScopes.Add(new ClientScope { ClientId = serviceM2M.Id, Scope = StandardScopes.ApiRead });
            _context.ClientScopes.Add(new ClientScope { ClientId = serviceM2M.Id, Scope = StandardScopes.MrWhoMetrics });

            _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = OpenIddictConstants.Permissions.Endpoints.Token });
            _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = OpenIddictConstants.Permissions.GrantTypes.ClientCredentials });
            _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = $"scp:{StandardScopes.MrWhoUse}" });
            _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = $"scp:{StandardScopes.MrWhoMetrics}" });
            await _context.SaveChangesAsync();
            _logger.LogInformation("Created standard service M2M client 'mrwho_m2m' (scopes mrwho.use, api.read, mrwho.metrics)");
        }
        else
        {
            bool changed = false;
            if (!serviceM2M.Scopes.Any(s => s.Scope == StandardScopes.MrWhoUse))
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = serviceM2M.Id, Scope = StandardScopes.MrWhoUse });
                changed = true;
            }
            if (!serviceM2M.Scopes.Any(s => s.Scope == StandardScopes.ApiRead))
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = serviceM2M.Id, Scope = StandardScopes.ApiRead });
                changed = true;
            }
            if (!serviceM2M.Scopes.Any(s => s.Scope == StandardScopes.MrWhoMetrics))
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = serviceM2M.Id, Scope = StandardScopes.MrWhoMetrics });
                changed = true;
            }
            if (!serviceM2M.Permissions.Any(p => p.Permission == $"scp:{StandardScopes.MrWhoUse}"))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = $"scp:{StandardScopes.MrWhoUse}" });
                changed = true;
            }
            if (!serviceM2M.Permissions.Any(p => p.Permission == OpenIddictConstants.Permissions.GrantTypes.ClientCredentials))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = OpenIddictConstants.Permissions.GrantTypes.ClientCredentials });
                changed = true;
            }
            if (!serviceM2M.Permissions.Any(p => p.Permission == OpenIddictConstants.Permissions.Endpoints.Token))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = OpenIddictConstants.Permissions.Endpoints.Token });
                changed = true;
            }
            if (!serviceM2M.Permissions.Any(p => p.Permission == $"scp:{StandardScopes.MrWhoMetrics}"))
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = serviceM2M.Id, Permission = $"scp:{StandardScopes.MrWhoMetrics}" });
                changed = true;
            }
            if (changed)
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated service M2M client 'mrwho_m2m' to include required scopes/permissions");
            }
        }

        // Ensure mrwho_m2m is registered with OpenIddict
        try
        {
            await SyncClientWithOpenIddictAsync(serviceM2M!);
            _logger.LogInformation("Synchronized service M2M client 'mrwho_m2m' with OpenIddict");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync service M2M client 'mrwho_m2m'");
            throw; // fail fast so invalid_client is surfaced early
        }

        // DEMO NUGET CLIENT (mrwho_demo_nuget)
        var nugetClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_demo_nuget");

        var cfgNuget = _clientOptions.Value.Nuget ?? new OidcClientsOptions.ClientOptions();
        if (string.IsNullOrWhiteSpace(cfgNuget.ClientId))
        {
            cfgNuget.ClientId = "mrwho_demo_nuget";
        }

        var nugetConfiguredRedirects = (IEnumerable<string>)(cfgNuget.RedirectUris ?? Array.Empty<string>());
        var nugetConfiguredPostLogout = (IEnumerable<string>)(cfgNuget.PostLogoutRedirectUris ?? Array.Empty<string>());

        if (nugetClient == null)
        {
            nugetClient = new Client
            {
                ClientId = cfgNuget.ClientId!,
                ClientSecret = string.IsNullOrWhiteSpace(cfgNuget.ClientSecret) ? null : cfgNuget.ClientSecret, // public client by default
                Name = "MrWho Demo NuGet App",
                Description = "Sample app using MrWho.ClientAuth NuGet",
                RealmId = demoRealm.Id,
                IsEnabled = true,
                ClientType = ClientType.Public,
                AllowAuthorizationCodeFlow = true,
                AllowClientCredentialsFlow = false,
                AllowPasswordFlow = false,
                AllowRefreshTokenFlow = true,
                RequirePkce = true,
                RequireClientSecret = false,
                CreatedBy = "System",
                AllowAccessToUserInfoEndpoint = true,
                AllowAccessToRevocationEndpoint = true,
                AllowAccessToIntrospectionEndpoint = false,
                ParMode = PushedAuthorizationMode.Enabled
            };
            _context.Clients.Add(nugetClient);
            await _context.SaveChangesAsync();

            foreach (var uri in nugetConfiguredRedirects)
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = nugetClient.Id, Uri = uri });
            }

            foreach (var uri in nugetConfiguredPostLogout)
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = nugetClient.Id, Uri = uri });
            }

            foreach (var scope in new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles, StandardScopes.OfflineAccess, StandardScopes.ApiRead })
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = nugetClient.Id, Scope = scope });
            }

            foreach (var p in new[]
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            })
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = nugetClient.Id, Permission = p });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created nuget demo client '{ClientId}' with configured/default localhost ports", nugetClient.ClientId);
        }
        else
        {
            // Backfill PAR and ensure configured URIs exist
            if (nugetClient.ParMode == null)
            {
                nugetClient.ParMode = PushedAuthorizationMode.Enabled;
                nugetClient.UpdatedAt = DateTime.UtcNow;
                nugetClient.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
            }

            var existingNugetRedirects = nugetClient.RedirectUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in nugetConfiguredRedirects)
            {
                if (!existingNugetRedirects.Contains(uri))
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = nugetClient.Id, Uri = uri });
                }
            }

            var existingNugetPostLogout = nugetClient.PostLogoutUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in nugetConfiguredPostLogout)
            {
                if (!existingNugetPostLogout.Contains(uri))
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = nugetClient.Id, Uri = uri });
                }
            }

            await _context.SaveChangesAsync();
        }

        // Default realm/client (postman)
        var defaultClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "postman_client");

        var cfgDefault = _clientOptions.Value.Default ?? new OidcClientsOptions.ClientOptions();
        if (string.IsNullOrWhiteSpace(cfgDefault.ClientId))
        {
            cfgDefault.ClientId = "postman_client";
        }

        var defaultRedirects = (IEnumerable<string>)(cfgDefault.RedirectUris ?? Array.Empty<string>());
        var defaultPostLogout = (IEnumerable<string>)(cfgDefault.PostLogoutRedirectUris ?? Array.Empty<string>());

        if (defaultClient == null)
        {
            defaultClient = new Client
            {
                ClientId = cfgDefault.ClientId!,
                ClientSecret = cfgDefault.ClientSecret ?? "postman_secret",
                Name = "Postman Test Client",
                Description = "Default test client for development",
                RealmId = (await _context.Realms.FirstAsync(r => r.Name == "demo")).Id,
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
                AllowAccessToIntrospectionEndpoint = true,
                // Enable PAR to match OIDC handler behavior when server advertises PAR
                ParMode = PushedAuthorizationMode.Enabled
            };
            _context.Clients.Add(defaultClient);
            await _context.SaveChangesAsync();

            foreach (var uri in new[] { "https://localhost:7001/callback", "http://localhost:5001/callback", "https://localhost:7002/", "https://localhost:7002/callback", "https://localhost:7002/signin-oidc" })
            {
                _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = defaultClient.Id, Uri = uri });
            }

            foreach (var uri in new[] { "https://localhost:7001/", "http://localhost:5001/", "https://localhost:7002/", "https://localhost:7002/signout-callback-oidc" })
            {
                _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = defaultClient.Id, Uri = uri });
            }

            foreach (var scope in new[] { StandardScopes.OpenId, StandardScopes.Email, StandardScopes.Profile, StandardScopes.Roles })
            {
                _context.ClientScopes.Add(new ClientScope { ClientId = defaultClient.Id, Scope = scope });
            }

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
            {
                _context.ClientPermissions.Add(new ClientPermission { ClientId = defaultClient.Id, Permission = permission });
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Created default client '{ClientId}'", defaultClient.ClientId);
        }
        else
        {
            // Clean legacy permissions
            var legacy = defaultClient.Permissions.Where(p => p.Permission.StartsWith("oidc:scope:") || p.Permission == "scp:openid" || p.Permission.StartsWith("scp:email") || p.Permission.StartsWith("scp:profile") || p.Permission.StartsWith("scp:roles")).ToList();
            if (legacy.Any())
            {
                _context.ClientPermissions.RemoveRange(legacy);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Cleaned {Count} legacy scope permissions from default client", legacy.Count);
            }
            if (defaultClient.ParMode == null)
            {
                defaultClient.ParMode = PushedAuthorizationMode.Enabled;
                defaultClient.UpdatedAt = DateTime.UtcNow;
                defaultClient.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
            }
            if (defaultClient.JarMode == null)
            {
                defaultClient.JarMode = JarMode.Optional;
                defaultClient.UpdatedAt = DateTime.UtcNow;
                defaultClient.UpdatedBy = "Backfill";
                await _context.SaveChangesAsync();
            }

            // Ensure configured redirects/post-logout exist
            var existingDefaultRedirects = defaultClient.RedirectUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in defaultRedirects)
            {
                if (!existingDefaultRedirects.Contains(uri))
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = defaultClient.Id, Uri = uri });
                }
            }

            var existingDefaultPostLogout = defaultClient.PostLogoutUris.Select(r => r.Uri).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var uri in defaultPostLogout)
            {
                if (!existingDefaultPostLogout.Contains(uri))
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = defaultClient.Id, Uri = uri });
                }
            }

            await _context.SaveChangesAsync();
        }
    }

    public async Task InitializeDefaultRealmAndClientsAsync()
    {
        // Reuse the comprehensive initializer to ensure defaults are present
        await InitializeEssentialDataAsync();
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
            // Determine if this client requires a secret (confidential or machine with RequireClientSecret=true)
            bool requiresSecret = (client.ClientType == ClientType.Confidential || client.ClientType == ClientType.Machine) && client.RequireClientSecret;

            // Try find existing OpenIddict app first
            var existingClient = await _applicationManager.FindByClientIdAsync(client.ClientId);

            // First pass using the supplied client instance
            var descriptor = BuildDescriptor(client);

            // Treat placeholder marker as absent
            if (descriptor.ClientSecret == "{HASHED}")
            {
                descriptor.ClientSecret = null; // force retrieval path
            }

            // If a secret is required but not present on the descriptor, fetch the current client from DB
            if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret))
            {
                var dbClient = await _context.Clients
                    .AsNoTracking()
                    .Include(c => c.RedirectUris)
                    .Include(c => c.PostLogoutUris)
                    .Include(c => c.Scopes)
                    .Include(c => c.Permissions)
                    .FirstOrDefaultAsync(c => c.Id == client.Id || c.ClientId == client.ClientId);
                if (dbClient != null)
                {
                    if (dbClient.ClientSecret == "{HASHED}")
                    {
                        dbClient.ClientSecret = null; // placeholder
                    }

                    var dbDescriptor = BuildDescriptor(dbClient);
                    if (!string.IsNullOrWhiteSpace(dbDescriptor.ClientSecret) && dbDescriptor.ClientSecret != "{HASHED}")
                    {
                        descriptor.ClientSecret = dbDescriptor.ClientSecret;
                    }
                }
            }

            // Attempt to resolve plaintext from secret history (preferred) when still missing or placeholder
            if (requiresSecret && (string.IsNullOrWhiteSpace(descriptor.ClientSecret) || descriptor.ClientSecret == "{HASHED}"))
            {
                if (_clientSecretService != null)
                {
                    var plain = await _clientSecretService.GetActivePlaintextAsync(client.ClientId);
                    if (!string.IsNullOrWhiteSpace(plain))
                    {
                        descriptor.ClientSecret = plain;
                        _logger.LogDebug("Resolved active plaintext secret for client {ClientId} from history for OpenIddict sync", client.ClientId);
                    }
                }
            }

            // If still missing, try pulling the stored secret from the OpenIddict EF entity (hashed or raw depending on config)
            if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret) && existingClient is not null)
            {
                if (existingClient is OpenIddictEntityFrameworkCoreApplication efApp && !string.IsNullOrWhiteSpace(efApp.ClientSecret))
                {
                    descriptor.ClientSecret = efApp.ClientSecret; // reuse stored hashed secret (can't verify against admin app if wrong)
                    _logger.LogDebug("Reused existing stored secret value for client {ClientId} from OpenIddict store", client.ClientId);
                }
            }

            // If a secret is required but we still didn't set one on the descriptor,
            // then: creation requires a secret; update will be skipped to avoid validation error and preserve existing secret.
            if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret))
            {
                if (existingClient is null)
                {
                    _logger.LogWarning("Skipping OpenIddict sync for client '{ClientId}': confidential/machine app requires a secret to be created (no history yet).", client.ClientId);
                    return;
                }
                else
                {
                    _logger.LogWarning("Skipping OpenIddict update for client '{ClientId}': secret is redacted/unknown. Rotate the secret to repair.", client.ClientId);
                    return;
                }
            }

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
