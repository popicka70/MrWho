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
/// Admin endpoints to manage dynamic client registration approvals.
/// </summary>
[ApiController]
[Route("api/client-registrations")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ClientRegistrationApprovalsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IOidcClientService _clientSync;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<ClientRegistrationApprovalsController> _logger;

    public ClientRegistrationApprovalsController(ApplicationDbContext db, IOidcClientService clientSync, IOpenIddictScopeManager scopeManager, ILogger<ClientRegistrationApprovalsController> logger)
    {
        _db = db; _clientSync = clientSync; _scopeManager = scopeManager; _logger = logger;
    }

    [HttpGet("pending")]
    public async Task<ActionResult<IEnumerable<object>>> GetPending([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        if (page < 1) page = 1; if (pageSize < 1 || pageSize > 100) pageSize = 20;
        var query = _db.PendingClientRegistrations.Where(p => p.Status == ClientRegistrationStatus.Pending)
                                                  .OrderByDescending(p => p.SubmittedAt);
        var total = await query.CountAsync();
        var items = await query.Skip((page - 1) * pageSize).Take(pageSize)
            .Select(p => new
            {
                p.Id,
                p.SubmittedAt,
                p.SubmittedByUserName,
                p.ClientName,
                p.TokenEndpointAuthMethod,
                p.Scope,
                RedirectUris = p.RedirectUrisCsv
            })
            .ToListAsync();
        return Ok(new { total, page, pageSize, items });
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<object>> Get(string id)
    {
        var rec = await _db.PendingClientRegistrations.FirstOrDefaultAsync(x => x.Id == id);
        if (rec == null) return NotFound();
        return Ok(new
        {
            rec.Id,
            rec.Status,
            rec.SubmittedAt,
            rec.SubmittedByUserId,
            rec.SubmittedByUserName,
            rec.ReviewedAt,
            rec.ReviewedBy,
            rec.ReviewReason,
            rec.ClientName,
            rec.TokenEndpointAuthMethod,
            rec.Scope,
            rec.RedirectUrisCsv,
            request = JsonSerializer.Deserialize<DynamicClientRegistrationRequest>(rec.RawRequestJson)
        });
    }

    [HttpPost("{id}/approve")]
    public async Task<ActionResult> Approve(string id)
    {
        var rec = await _db.PendingClientRegistrations.FirstOrDefaultAsync(x => x.Id == id);
        if (rec == null) return NotFound();
        if (rec.Status != ClientRegistrationStatus.Pending) return Conflict("Registration already processed");

        var request = JsonSerializer.Deserialize<DynamicClientRegistrationRequest>(rec.RawRequestJson) ?? new();

        // Determine grants
        var grants = request.GrantTypes ?? new List<string>();
        var wantsCode = grants.Contains("authorization_code", StringComparer.OrdinalIgnoreCase);
        var wantsClientCreds = grants.Contains("client_credentials", StringComparer.OrdinalIgnoreCase);
        var wantsRefresh = grants.Contains("refresh_token", StringComparer.OrdinalIgnoreCase) || wantsCode;

        // For MVP put everything in default realm
        var defaultRealm = await _db.Realms.FirstOrDefaultAsync(r => r.Name == "default") ?? await CreateDefaultRealmAsync();

        // Generate client id and secret if required
        var clientId = Guid.NewGuid().ToString("n");
        var secret = wantsClientCreds || (request.TokenEndpointAuthMethod is not null && !string.Equals(request.TokenEndpointAuthMethod, "none", StringComparison.OrdinalIgnoreCase))
            ? GenerateSecret()
            : null;

        var client = new Client
        {
            ClientId = clientId,
            ClientSecret = secret,
            Name = request.ClientName ?? clientId,
            Description = "Dynamically registered client (approved)",
            RealmId = defaultRealm.Id,
            IsEnabled = true,
            ClientType = secret == null ? ClientType.Public : (wantsClientCreds && !wantsCode ? ClientType.Machine : ClientType.Confidential),
            AllowAuthorizationCodeFlow = wantsCode,
            AllowClientCredentialsFlow = wantsClientCreds,
            AllowRefreshTokenFlow = wantsRefresh,
            AllowPasswordFlow = false,
            RequirePkce = wantsCode,
            RequireClientSecret = secret != null,
            CreatedBy = User?.Identity?.Name ?? "registration-approval",
            AllowAccessToUserInfoEndpoint = wantsCode,
            AllowAccessToRevocationEndpoint = true,
            AllowAccessToIntrospectionEndpoint = wantsClientCreds
        };

        _db.Clients.Add(client);
        await _db.SaveChangesAsync();

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
        if (wantsCode && !normalizedScopes.Contains(StandardScopes.OpenId))
        {
            _db.ClientScopes.Add(new ClientScope { ClientId = client.Id, Scope = StandardScopes.OpenId });
        }

        await _db.SaveChangesAsync();

        // Sync with OpenIddict
        await _clientSync.SyncClientWithOpenIddictAsync(client);

        // Mark as approved
        rec.Status = ClientRegistrationStatus.Approved;
        rec.ReviewedAt = DateTime.UtcNow;
        rec.ReviewedBy = User.Identity?.Name;
        rec.CreatedClientDbId = client.Id;
        rec.CreatedClientPublicId = client.ClientId;
        await _db.SaveChangesAsync();

        _logger.LogInformation("Approved dynamic client registration {RegistrationId} -> client {ClientId}", rec.Id, client.ClientId);
        return Ok(new
        {
            rec.Id,
            status = rec.Status.ToString().ToLowerInvariant(),
            client_id = client.ClientId,
            client_secret = client.ClientSecret
        });
    }

    [HttpPost("{id}/reject")]
    public async Task<ActionResult> Reject(string id, [FromBody] RejectRequest? body)
    {
        var rec = await _db.PendingClientRegistrations.FirstOrDefaultAsync(x => x.Id == id);
        if (rec == null) return NotFound();
        if (rec.Status != ClientRegistrationStatus.Pending) return Conflict("Registration already processed");

        rec.Status = ClientRegistrationStatus.Rejected;
        rec.ReviewedAt = DateTime.UtcNow;
        rec.ReviewedBy = User.Identity?.Name;
        rec.ReviewReason = body?.Reason;
        await _db.SaveChangesAsync();

        _logger.LogInformation("Rejected dynamic client registration {RegistrationId} by {User}", rec.Id, User.Identity?.Name);
        return Ok(new { rec.Id, status = rec.Status.ToString().ToLowerInvariant() });
    }

    private async Task<Realm> CreateDefaultRealmAsync()
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
        await _db.SaveChangesAsync();
        return realm;
    }

    private static string GenerateSecret()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(48);
        return Convert.ToBase64String(bytes);
    }

    public class RejectRequest { public string? Reason { get; set; } }
}
