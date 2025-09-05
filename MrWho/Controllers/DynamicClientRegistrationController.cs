using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;

namespace MrWho.Controllers;

/// <summary>
/// Implements a minimal protected dynamic client registration endpoint (admin authenticated only for now).
/// RFC 7591 subset.
/// </summary>
[Route("connect/register")]
[ApiController]
[Authorize] // admin portal users only initial slice
public class DynamicClientRegistrationController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IOidcClientService _clientSync;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<DynamicClientRegistrationController> _logger;

    public DynamicClientRegistrationController(ApplicationDbContext db, IOidcClientService clientSync, IOpenIddictScopeManager scopeManager, ILogger<DynamicClientRegistrationController> logger)
    {
        _db = db; _clientSync = clientSync; _scopeManager = scopeManager; _logger = logger;
    }

    [HttpPost]
    [Produces("application/json")]
    public async Task<IActionResult> Register([FromBody] DynamicClientRegistrationRequest request, CancellationToken ct)
    {
        if (request == null) return BadRequest(new { error = "invalid_request", error_description = "Missing body" });
        var (ok, error) = DynamicClientRegistrationValidation.Validate(request);
        if (!ok) return BadRequest(new { error = "invalid_client_metadata", error_description = error });

        // Determine grants
        var grants = request.GrantTypes ?? new List<string>();
        var wantsCode = grants.Contains("authorization_code", StringComparer.OrdinalIgnoreCase);
        var wantsClientCreds = grants.Contains("client_credentials", StringComparer.OrdinalIgnoreCase);
        var wantsRefresh = grants.Contains("refresh_token", StringComparer.OrdinalIgnoreCase);

        // Build new client
        var clientId = Guid.NewGuid().ToString("n");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var secret = wantsClientCreds || request.TokenEndpointAuthMethod is not null && !string.Equals(request.TokenEndpointAuthMethod, "none", StringComparison.OrdinalIgnoreCase)
            ? GenerateSecret()
            : null;

        // For MVP put everything in default realm
        var defaultRealm = await _db.Realms.FirstOrDefaultAsync(r => r.Name == "default", ct) ?? await CreateDefaultRealmAsync(ct);

        var client = new Client
        {
            ClientId = clientId,
            ClientSecret = secret,
            Name = request.ClientName ?? clientId,
            Description = "Dynamically registered client",
            RealmId = defaultRealm.Id,
            IsEnabled = true,
            ClientType = secret == null ? ClientType.Public : (wantsClientCreds && !wantsCode ? ClientType.Machine : ClientType.Confidential),
            AllowAuthorizationCodeFlow = wantsCode,
            AllowClientCredentialsFlow = wantsClientCreds,
            AllowRefreshTokenFlow = wantsRefresh || wantsCode, // allow refresh when code flow implied
            AllowPasswordFlow = false,
            RequirePkce = wantsCode, // enforce for code clients
            RequireClientSecret = secret != null,
            CreatedBy = User?.Identity?.Name ?? "registration",
            AllowAccessToUserInfoEndpoint = wantsCode,
            AllowAccessToRevocationEndpoint = true,
            AllowAccessToIntrospectionEndpoint = wantsClientCreds
        };

        _db.Clients.Add(client);
        await _db.SaveChangesAsync(ct);

        // Redirect URIs
        if (wantsCode && request.RedirectUris != null)
        {
            foreach (var uri in request.RedirectUris.Distinct())
            {
                if (Uri.IsWellFormedUriString(uri, UriKind.Absolute))
                    _db.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = client.Id, Uri = uri });
            }
        }
        if (wantsCode && request.PostLogoutRedirectUris != null)
        {
            foreach (var uri in request.PostLogoutRedirectUris.Distinct())
            {
                if (Uri.IsWellFormedUriString(uri, UriKind.Absolute))
                    _db.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = client.Id, Uri = uri });
            }
        }

        // Scopes
        var normalizedScopes = new List<string>();
        if (!string.IsNullOrWhiteSpace(request.Scope))
        {
            var raw = request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                    .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var s in raw)
            {
                if (await _scopeManager.FindByNameAsync(s) != null)
                {
                    _db.ClientScopes.Add(new ClientScope { ClientId = client.Id, Scope = s });
                    normalizedScopes.Add(s);
                }
            }
        }
        // Always include openid if code flow; add profile as a convenience demo
        if (wantsCode && !normalizedScopes.Contains(StandardScopes.OpenId))
        {
            _db.ClientScopes.Add(new ClientScope { ClientId = client.Id, Scope = StandardScopes.OpenId });
            normalizedScopes.Add(StandardScopes.OpenId);
        }

        await _db.SaveChangesAsync(ct);

        // Persist + sync with OpenIddict
        await _clientSync.SyncClientWithOpenIddictAsync(client);

        var response = new DynamicClientRegistrationResponse
        {
            ClientId = clientId,
            ClientSecret = secret,
            ClientIdIssuedAt = now,
            ClientSecretExpiresAt = 0,
            RedirectUris = request.RedirectUris,
            PostLogoutRedirectUris = request.PostLogoutRedirectUris,
            GrantTypes = request.GrantTypes,
            ResponseTypes = request.ResponseTypes ?? (wantsCode ? new[] { "code" } : null),
            TokenEndpointAuthMethod = secret == null ? "none" : "client_secret_post",
            Scope = normalizedScopes.Count > 0 ? string.Join(' ', normalizedScopes) : null
        };

        return Ok(response);
    }

    private async Task<Realm> CreateDefaultRealmAsync(CancellationToken ct)
    {
        var realm = new Realm
        {
            Name = "default",
            DisplayName = "Default Realm",
            Description = "Auto-created default realm",
            IsEnabled = true,
            CreatedBy = "system"
        };
        _db.Realms.Add(realm);
        await _db.SaveChangesAsync(ct);
        return realm;
    }

    private static string GenerateSecret()
    {
        var bytes = RandomNumberGenerator.GetBytes(48);
        return Convert.ToBase64String(bytes);
    }
}
