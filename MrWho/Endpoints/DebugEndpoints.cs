using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using MrWho.Data;
using MrWho.Services;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;

namespace MrWho.Endpoints;

// Index
public sealed record DebugIndexRequest() : IRequest<IResult>;
public sealed class DebugIndexHandler : IRequestHandler<DebugIndexRequest, IResult>
{
    public Task<IResult> Handle(DebugIndexRequest request, CancellationToken cancellationToken)
    {
        var payload = new
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
        };
        return Task.FromResult(Results.Ok(payload) as IResult);
    }
}

// /debug/client-cookies
public sealed record ClientCookiesDebugRequest(HttpContext HttpContext) : IRequest<IResult>;
public sealed class ClientCookiesDebugHandler : IRequestHandler<ClientCookiesDebugRequest, IResult>
{
    private readonly IClientCookieConfigurationService _cookieService;

    public ClientCookiesDebugHandler(IClientCookieConfigurationService cookieService)
        => _cookieService = cookieService;

    public Task<IResult> Handle(ClientCookiesDebugRequest request, CancellationToken cancellationToken)
    {
        var context = request.HttpContext;
        var configurations = _cookieService.GetAllClientConfigurations();
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

        var result = new
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
            AllRequestCookies = context.Request.Cookies.Select(c => new { Name = c.Key, Length = c.Value.Length }),
            Timestamp = DateTime.UtcNow
        };

        return Task.FromResult(Results.Ok(result) as IResult);
    }
}

// /debug/client-info (postman)
public sealed record ClientInfoRequest() : IRequest<IResult>;
public sealed class ClientInfoHandler : IRequestHandler<ClientInfoRequest, IResult>
{
    private readonly IOidcClientService _oidcClientService;

    public ClientInfoHandler(IOidcClientService oidcClientService) => _oidcClientService = oidcClientService;

    public async Task<IResult> Handle(ClientInfoRequest request, CancellationToken cancellationToken)
    {
        var clients = await _oidcClientService.GetEnabledClientsAsync();
        var postmanClient = clients.FirstOrDefault(c => c.ClientId == "postman_client");
        if (postmanClient == null)
        {
            return Results.NotFound("Postman client not found");
        }

        var payload = new
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
        };

        return Results.Ok(payload);
    }
}

// /debug/db-client-config
public sealed record DbClientConfigRequest() : IRequest<IResult>;
public sealed class DbClientConfigHandler : IRequestHandler<DbClientConfigRequest, IResult>
{
    private readonly IOidcClientService _oidcClientService;
    private readonly IOpenIddictApplicationManager _applicationManager;

    public DbClientConfigHandler(IOpenIddictApplicationManager applicationManager, IOidcClientService oidcClientService)
    {
        _applicationManager = applicationManager;
        _oidcClientService = oidcClientService;
    }

    public async Task<IResult> Handle(DbClientConfigRequest request, CancellationToken cancellationToken)
    {
        var clients = await _oidcClientService.GetEnabledClientsAsync();
        var clientConfigs = new List<object>();

        foreach (var client in clients)
        {
            var openIddictClient = await _applicationManager.FindByClientIdAsync(client.ClientId);
            if (openIddictClient != null)
            {
                clientConfigs.Add(new
                {
                    ClientId = await _applicationManager.GetClientIdAsync(openIddictClient),
                    DisplayName = await _applicationManager.GetDisplayNameAsync(openIddictClient),
                    RedirectUris = await _applicationManager.GetRedirectUrisAsync(openIddictClient),
                    PostLogoutRedirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(openIddictClient),
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
    }
}

// /debug/admin-client-info
public sealed record AdminClientInfoRequest() : IRequest<IResult>;
public sealed class AdminClientInfoHandler : IRequestHandler<AdminClientInfoRequest, IResult>
{
    private readonly IOidcClientService _oidcClientService;

    public AdminClientInfoHandler(IOidcClientService oidcClientService) => _oidcClientService = oidcClientService;

    public async Task<IResult> Handle(AdminClientInfoRequest request, CancellationToken cancellationToken)
    {
        var clients = await _oidcClientService.GetEnabledClientsAsync();
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
            AdminCredentials = new { Username = "admin@mrwho.local", Password = "Adm1n#2025!G7x" }
        });
    }
}

// /debug/demo1-client-info
public sealed record Demo1ClientInfoRequest() : IRequest<IResult>;
public sealed class Demo1ClientInfoHandler : IRequestHandler<Demo1ClientInfoRequest, IResult>
{
    private readonly IOidcClientService _oidcClientService;

    public Demo1ClientInfoHandler(IOidcClientService oidcClientService) => _oidcClientService = oidcClientService;

    public async Task<IResult> Handle(Demo1ClientInfoRequest request, CancellationToken cancellationToken)
    {
        var clients = await _oidcClientService.GetEnabledClientsAsync();
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
            Demo1Credentials = new { Username = "demo1@example.com", Password = "Demo123" }
        });
    }
}

// /debug/essential-data
public sealed record EssentialDataRequest() : IRequest<IResult>;
public sealed class EssentialDataHandler : IRequestHandler<EssentialDataRequest, IResult>
{
    private readonly ApplicationDbContext _context;

    public EssentialDataHandler(ApplicationDbContext context) => _context = context;

    public async Task<IResult> Handle(EssentialDataRequest request, CancellationToken cancellationToken)
    {
        var adminRealm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == "admin", cancellationToken);
        var adminClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web", cancellationToken);
        var adminUser = await _context.Users.FirstOrDefaultAsync(u => u.UserName == "admin@mrwho.local", cancellationToken);

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
                AdminCredentials = new { Username = "admin@mrwho.local", Password = "Adm1n#2025!G7x" }
            }
        });
    }
}

// /debug/client-permissions
public sealed record ClientPermissionsRequest() : IRequest<IResult>;
public sealed class ClientPermissionsHandler : IRequestHandler<ClientPermissionsRequest, IResult>
{
    private readonly ApplicationDbContext _context;

    public ClientPermissionsHandler(ApplicationDbContext context) => _context = context;

    public async Task<IResult> Handle(ClientPermissionsRequest request, CancellationToken cancellationToken)
    {
        var adminClient = await _context.Clients
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web", cancellationToken);

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
    }
}

// /debug/reset-admin-client (POST, dev only)
public sealed record ResetAdminClientRequest() : IRequest<IResult>;
public sealed class ResetAdminClientHandler : IRequestHandler<ResetAdminClientRequest, IResult>
{
    private readonly ApplicationDbContext _context;
    private readonly IOidcClientService _clientService;
    private readonly ILogger<ResetAdminClientHandler> _logger;
    private readonly IHostEnvironment _env;

    public ResetAdminClientHandler(ApplicationDbContext context, IOidcClientService oidClientService, ILogger<ResetAdminClientHandler> logger, IHostEnvironment env)
    {
        _context = context;
        _clientService = oidClientService;
        _logger = logger;
        _env = env;
    }

    public async Task<IResult> Handle(ResetAdminClientRequest request, CancellationToken cancellationToken)
    {
        if (!_env.IsDevelopment())
        {
            return Results.BadRequest("This endpoint is only available in development");
        }

        _logger.LogWarning("RESETTING ADMIN CLIENT - This will delete and recreate the admin client");
        _logger.LogWarning("Ensure you have a backup of your database before proceeding!");

        var existingClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web", cancellationToken);

        if (existingClient != null)
        {
            _context.Clients.Remove(existingClient);
            await _context.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Deleted existing admin client");
        }

        try
        {
            await _clientService.InitializeEssentialDataAsync();
            return Results.Ok(new { message = "Admin client reset successfully", timestamp = DateTime.UtcNow });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error recreating admin client");
            return Results.Problem($"Error recreating admin client: {ex.Message}");
        }
    }
}

// /debug/fix-api-permissions (POST, dev only)
public sealed record FixApiPermissionsRequest() : IRequest<IResult>;
public sealed class FixApiPermissionsHandler : IRequestHandler<FixApiPermissionsRequest, IResult>
{
    private readonly ApplicationDbContext _context;
    private readonly IOidcClientService _oidcClientService;
    private readonly ILogger<FixApiPermissionsHandler> _logger;
    private readonly IHostEnvironment _env;

    public FixApiPermissionsHandler(ApplicationDbContext context, IOidcClientService oidcClientService, ILogger<FixApiPermissionsHandler> logger, IHostEnvironment env)
    {
        _context = context;
        _oidcClientService = oidcClientService;
        _logger = logger;
        _env = env;
    }

    public async Task<IResult> Handle(FixApiPermissionsRequest request, CancellationToken cancellationToken)
    {
        if (!_env.IsDevelopment())
        {
            return Results.BadRequest("This endpoint is only available in development");
        }

        _logger.LogInformation("FIXING API PERMISSIONS - Updating permission format for all clients with API scopes");
        var clientsWithApiScopes = await _context.Clients
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Where(c => c.Scopes.Any(s => s.Scope.StartsWith("api.")))
            .ToListAsync(cancellationToken);

        var updatedClients = new List<string>();

        foreach (var client in clientsWithApiScopes)
        {
            var hasChanges = false;

            var oldPermissions = client.Permissions
                .Where(p => p.Permission.StartsWith("oidc:scope:api.") || (p.Permission.StartsWith("api.") && !p.Permission.StartsWith("scp:")))
                .ToList();

            if (oldPermissions.Any())
            {
                _logger.LogInformation("Removing old API permissions for client {ClientId}: {Permissions}", client.ClientId, string.Join(", ", oldPermissions.Select(p => p.Permission)));
                foreach (var oldPerm in oldPermissions)
                {
                    _context.ClientPermissions.Remove(oldPerm);
                }
                hasChanges = true;
            }

            var apiScopes = client.Scopes.Where(s => s.Scope.StartsWith("api.")).Select(s => s.Scope).ToList();
            foreach (var apiScope in apiScopes)
            {
                var correctPermission = $"scp:{apiScope}";
                if (!client.Permissions.Any(p => p.Permission == correctPermission))
                {
                    _logger.LogInformation("Adding correct API permission for client {ClientId}: {Permission}", client.ClientId, correctPermission);
                    _context.ClientPermissions.Add(new MrWho.Models.ClientPermission { ClientId = client.Id, Permission = correctPermission });
                    hasChanges = true;
                }
            }

            if (hasChanges)
            {
                updatedClients.Add(client.ClientId);
                try
                {
                    await _oidcClientService.SyncClientWithOpenIddictAsync(client);
                    _logger.LogInformation("Re-synced client {ClientId} with OpenIddict", client.ClientId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to re-sync client {ClientId} with OpenIddict", client.ClientId);
                }
            }
        }

        if (updatedClients.Any())
        {
            await _context.SaveChangesAsync(cancellationToken);
            _logger.LogInformation("Updated API permissions for clients: {Clients}", string.Join(", ", updatedClients));
            return Results.Ok(new { message = "API permissions fixed successfully", updatedClients, timestamp = DateTime.UtcNow });
        }

        return Results.Ok(new { message = "No API permission fixes needed", timestamp = DateTime.UtcNow });
    }
}

// /debug/openiddict-scopes
public sealed record OpenIddictScopesRequest() : IRequest<IResult>;
public sealed class OpenIddictScopesHandler : IRequestHandler<OpenIddictScopesRequest, IResult>
{
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ApplicationDbContext _context;

    public OpenIddictScopesHandler(IOpenIddictScopeManager scopeManager, ApplicationDbContext context)
    {
        _scopeManager = scopeManager;
        _context = context;
    }

    public async Task<IResult> Handle(OpenIddictScopesRequest request, CancellationToken cancellationToken)
    {
        var openIddictScopes = new List<object>();
        var databaseScopes = await _context.Scopes
            .Where(s => s.IsEnabled)
            .OrderBy(s => s.Name)
            .ToListAsync(cancellationToken);

        foreach (var dbScope in databaseScopes)
        {
            var openIddictScope = await _scopeManager.FindByNameAsync(dbScope.Name);
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
                    Id = await _scopeManager.GetIdAsync(openIddictScope),
                    Name = await _scopeManager.GetNameAsync(openIddictScope),
                    DisplayName = await _scopeManager.GetDisplayNameAsync(openIddictScope),
                    Description = await _scopeManager.GetDescriptionAsync(openIddictScope),
                    Resources = await _scopeManager.GetResourcesAsync(openIddictScope)
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
    }
}

// /debug/sync-scopes (POST, dev only)
public sealed record SyncScopesRequest() : IRequest<IResult>;
public sealed class SyncScopesHandler : IRequestHandler<SyncScopesRequest, IResult>
{
    private readonly IOpenIddictScopeSyncService _scopeSyncService;
    private readonly ILogger<SyncScopesHandler> _logger;
    private readonly IHostEnvironment _env;

    public SyncScopesHandler(IOpenIddictScopeSyncService scopeSyncService, ILogger<SyncScopesHandler> logger, IHostEnvironment env)
    {
        _scopeSyncService = scopeSyncService;
        _logger = logger;
        _env = env;
    }

    public async Task<IResult> Handle(SyncScopesRequest request, CancellationToken cancellationToken)
    {
        if (!_env.IsDevelopment())
        {
            return Results.BadRequest("This endpoint is only available in development");
        }

        try
        {
            await _scopeSyncService.SynchronizeAllScopesAsync();
            return Results.Ok(new { message = "All scopes synchronized with OpenIddict successfully", timestamp = DateTime.UtcNow });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to synchronize scopes with OpenIddict");
            return Results.Problem($"Failed to synchronize scopes: {ex.Message}");
        }
    }
}

// /debug/userinfo-test (GET, authorized)
public sealed record UserInfoTestRequest(HttpContext HttpContext) : IRequest<IResult>;
public sealed class UserInfoTestHandler : IRequestHandler<UserInfoTestRequest, IResult>
{
    private readonly MrWho.Handlers.IUserInfoHandler _userInfoHandler;
    private readonly ILogger<UserInfoTestHandler> _logger;

    public UserInfoTestHandler(MrWho.Handlers.IUserInfoHandler userInfoHandler, ILogger<UserInfoTestHandler> logger)
    {
        _userInfoHandler = userInfoHandler;
        _logger = logger;
    }

    public async Task<IResult> Handle(UserInfoTestRequest request, CancellationToken cancellationToken)
    {
        var context = request.HttpContext;
        _logger.LogInformation("Testing UserInfo handler directly");
        if (!context.User.Identity?.IsAuthenticated == true)
        {
            return Results.Unauthorized();
        }

        try
        {
            var result = await _userInfoHandler.HandleUserInfoRequestAsync(context);
            _logger.LogInformation("UserInfo handler returned result type: {ResultType}", result.GetType().Name);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error testing UserInfo handler");
            return Results.Problem($"Error testing UserInfo handler: {ex.Message}");
        }
    }
}

// /debug/current-claims (GET, authorized)
public sealed record CurrentClaimsRequest(HttpContext HttpContext) : IRequest<IResult>;
public sealed class CurrentClaimsHandler : IRequestHandler<CurrentClaimsRequest, IResult>
{
    private readonly ILogger<CurrentClaimsHandler> _logger;

    public CurrentClaimsHandler(ILogger<CurrentClaimsHandler> logger) => _logger = logger;

    public Task<IResult> Handle(CurrentClaimsRequest request, CancellationToken cancellationToken)
    {
        var context = request.HttpContext;
        _logger.LogInformation("Checking current claims in ClaimsPrincipal");
        if (!context.User.Identity?.IsAuthenticated == true)
        {
            return Task.FromResult(Results.Json(new { IsAuthenticated = false, Message = "User is not authenticated" }) as IResult);
        }

        var claims = context.User.Claims.Select(c => new { Type = c.Type, Value = c.Value, Issuer = c.Issuer }).ToList();
        return Task.FromResult(Results.Json(new
        {
            IsAuthenticated = true,
            ClaimsCount = claims.Count,
            IdentityName = context.User.Identity?.Name,
            AuthenticationType = context.User.Identity?.AuthenticationType ?? string.Empty,
            Claims = claims
        }) as IResult);
    }
}

// /debug/identity-resources
public sealed record IdentityResourcesRequest() : IRequest<IResult>;
public sealed class IdentityResourcesHandler : IRequestHandler<IdentityResourcesRequest, IResult>
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<IdentityResourcesHandler> _logger;

    public IdentityResourcesHandler(ApplicationDbContext context, ILogger<IdentityResourcesHandler> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<IResult> Handle(IdentityResourcesRequest request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Checking identity resources in database");

        var identityResources = await _context.IdentityResources
            .Include(ir => ir.UserClaims)
            .ToListAsync(cancellationToken);

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
    }
}

// /debug/user-claims/{userId}
public sealed record UserClaimsByUserIdRequest(string UserId) : IRequest<IResult>;
public sealed class UserClaimsByUserIdHandler : IRequestHandler<UserClaimsByUserIdRequest, IResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<UserClaimsByUserIdHandler> _logger;

    public UserClaimsByUserIdHandler(UserManager<IdentityUser> userManager, ILogger<UserClaimsByUserIdHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<IResult> Handle(UserClaimsByUserIdRequest request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Checking claims for user {UserId}", request.UserId);
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return Results.NotFound($"User with ID '{request.UserId}' not found");
        }

        var claims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

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
    }
}

// /debug/all-users
public sealed record AllUsersRequest() : IRequest<IResult>;
public sealed class AllUsersHandler : IRequestHandler<AllUsersRequest, IResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<AllUsersHandler> _logger;

    public AllUsersHandler(UserManager<IdentityUser> userManager, ILogger<AllUsersHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<IResult> Handle(AllUsersRequest request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Listing all users in the system");
        var users = _userManager.Users.ToList();
        var userDetails = new List<object>();

        foreach (var user in users)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
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

        var result = new { TotalUsers = users.Count, Users = userDetails };
        return Results.Json(result);
    }
}

// /debug/find-user-by-subject/{subject}
public sealed record FindUserBySubjectRequest(string Subject) : IRequest<IResult>;
public sealed class FindUserBySubjectHandler : IRequestHandler<FindUserBySubjectRequest, IResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<FindUserBySubjectHandler> _logger;

    public FindUserBySubjectHandler(UserManager<IdentityUser> userManager, ILogger<FindUserBySubjectHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<IResult> Handle(FindUserBySubjectRequest request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Looking for user with subject/ID {Subject}", request.Subject);

        var user = await _userManager.FindByIdAsync(request.Subject) ?? await _userManager.FindByNameAsync(request.Subject);
        if (user == null)
        {
            _logger.LogError("NO USER FOUND: Subject/ID or username '{Subject}' does not exist in database", request.Subject);
            return Results.NotFound($"No user found with subject/ID or username '{request.Subject}'");
        }

        var claims = await _userManager.GetClaimsAsync(user);
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
    }
}

// /debug/check-subject-3b9262de
public sealed record CheckSpecificSubjectRequest() : IRequest<IResult>;
public sealed class CheckSpecificSubjectHandler : IRequestHandler<CheckSpecificSubjectRequest, IResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<CheckSpecificSubjectHandler> _logger;

    public CheckSpecificSubjectHandler(UserManager<IdentityUser> userManager, ILogger<CheckSpecificSubjectHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<IResult> Handle(CheckSpecificSubjectRequest request, CancellationToken cancellationToken)
    {
        var subjectId = "3b9262de-0bbf-4ba1-9d58-d48f24ce1d05";
        _logger.LogInformation("DEBUGGING SPECIFIC SUBJECT: {SubjectId}", subjectId);

        var userById = await _userManager.FindByIdAsync(subjectId);
        _logger.LogInformation("User by ID: {Found}", userById?.UserName ?? "NOT FOUND");

        var userByName = await _userManager.FindByNameAsync(subjectId);
        _logger.LogInformation("User by Name: {Found}", userByName?.UserName ?? "NOT FOUND");

        var allUsers = _userManager.Users.Select(u => new { u.Id, u.UserName, u.Email }).ToList();
        return Results.Json(new
        {
            SearchedSubject = subjectId,
            UserFoundById = userById != null ? new { userById.Id, userById.UserName, userById.Email } : null,
            UserFoundByName = userByName != null ? new { userByName.Id, userByName.UserName, userByName.Email } : null,
            AllUsersInDatabase = allUsers,
            PossibleIssue = "Subject ID in authorization handler may not match any actual user ID"
        });
    }
}

// /debug/demo1-troubleshoot
public sealed record Demo1TroubleshootRequest() : IRequest<IResult>;
public sealed class Demo1TroubleshootHandler : IRequestHandler<Demo1TroubleshootRequest, IResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IOidcClientService _oidcClientService;
    private readonly IUserRealmValidationService _realmValidationService;
    private readonly ILogger<Demo1TroubleshootHandler> _logger;

    public Demo1TroubleshootHandler(
        UserManager<IdentityUser> userManager,
        IOidcClientService oidcClientService,
        IUserRealmValidationService realmValidationService,
        ILogger<Demo1TroubleshootHandler> logger)
    {
        _userManager = userManager;
        _oidcClientService = oidcClientService;
        _realmValidationService = realmValidationService;
        _logger = logger;
    }

    public async Task<IResult> Handle(Demo1TroubleshootRequest request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("DEMO1 COMPREHENSIVE TROUBLESHOOTING");

        var steps = new List<dynamic>();

        var demo1User = await _userManager.FindByNameAsync("demo1@example.com");
        steps.Add(new
        {
            Step = 1,
            Description = "Check Demo1 User Exists",
            Success = demo1User != null,
            Details = demo1User != null ? (object)new
            {
                UserId = demo1User.Id,
                UserName = demo1User.UserName,
                Email = demo1User.Email,
                EmailConfirmed = demo1User.EmailConfirmed
            } : "USER NOT FOUND"
        });

        if (demo1User != null)
        {
            var claims = await _userManager.GetClaimsAsync(demo1User);
            var realmClaim = claims.FirstOrDefault(c => c.Type == "realm")?.Value;
            steps.Add(new
            {
                Step = 2,
                Description = "Check Demo1 User Claims",
                Success = claims.Any(),
                Details = (object)new
                {
                    ClaimsCount = claims.Count,
                    RealmClaim = realmClaim ?? "NO REALM CLAIM",
                    AllClaims = claims.Select(c => new { c.Type, c.Value }).ToArray()
                }
            });

            var clients = await _oidcClientService.GetEnabledClientsAsync();
            var demo1Client = clients.FirstOrDefault(c => c.ClientId == "mrwho_demo1");
            steps.Add(new
            {
                Step = 3,
                Description = "Check Demo1 Client Exists",
                Success = demo1Client != null,
                Details = demo1Client != null ? (object)new
                {
                    demo1Client.ClientId,
                    demo1Client.Name,
                    demo1Client.IsEnabled,
                    RealmName = demo1Client.Realm.Name,
                    RealmEnabled = demo1Client.Realm.IsEnabled
                } : "CLIENT NOT FOUND"
            });

            if (demo1Client != null)
            {
                var realmValidation = await _realmValidationService.ValidateUserRealmAccessAsync(demo1User, "mrwho_demo1");
                steps.Add(new
                {
                    Step = 4,
                    Description = "Test Realm Validation",
                    Success = realmValidation.IsValid,
                    Details = (object)new
                    {
                        IsValid = realmValidation.IsValid,
                        Reason = realmValidation.Reason,
                        ClientRealm = realmValidation.ClientRealm,
                        ErrorCode = realmValidation.ErrorCode
                    }
                });
            }

            var passwordCheck = await _userManager.CheckPasswordAsync(demo1User, "Demo123");
            steps.Add(new
            {
                Step = 5,
                Description = "Test Password Validation",
                Success = passwordCheck,
                Details = (object)(passwordCheck ? "Password correct" : "Password INCORRECT")
            });
        }

        var allUsers = _userManager.Users.Select(u => new { u.Id, u.UserName, u.Email }).ToList();
        steps.Add(new
        {
            Step = 6,
            Description = "List All Users in System",
            Success = allUsers.Any(),
            Details = (object)new { TotalUsers = allUsers.Count, Users = allUsers }
        });

        var overallSuccess = steps.All(s => s.Success);
        var summary = new
        {
            OverallSuccess = overallSuccess,
            Issues = steps.Where(s => !s.Success).Select(s => $"Step {s.Step}: {s.Description}").ToArray(),
            NextSteps = !overallSuccess ? new[] { "Fix the failed steps above", "Re-run this debug endpoint to verify fixes" } : new[] { "All checks passed - the issue may be elsewhere in the authentication flow" }
        };

        return Results.Json(new { result = new { TestTimestamp = DateTime.UtcNow, Steps = steps }, summary });
    }
}
