using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services; // added
using MrWho.Shared;
using MrWho.Shared.Models;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ClientsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ClientsController> _logger;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IClientSecretService _clientSecretService; // added

    public ClientsController(
        ApplicationDbContext context, 
        ILogger<ClientsController> logger,
        IOpenIddictApplicationManager applicationManager,
        UserManager<IdentityUser> userManager,
        IClientSecretService clientSecretService) // added
    {
        _context = context;
        _logger = logger;
        _applicationManager = applicationManager;
        _userManager = userManager;
        _clientSecretService = clientSecretService;
    }

    /// <summary>
    /// Rotate client secret. Returns the new plaintext once. Admin-only.
    /// </summary>
    [HttpPost("{id}/rotate-secret")]
    public async Task<ActionResult<object>> RotateSecret(string id, [FromBody] RotateClientSecretRequest? request)
    {
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == id || c.ClientId == id);
        if (client is null)
            return NotFound("Client not found");

        var requiresSecret = (client.ClientType == ClientType.Confidential || client.ClientType == ClientType.Machine) && client.RequireClientSecret;
        if (!requiresSecret)
            return BadRequest("This client type does not use client secrets");

        var expiresAt = request?.ExpiresAtUtc;
        var retireOld = request?.RetireOld ?? true;

        var result = await _clientSecretService.SetNewSecretAsync(client.Id, providedPlaintext: request?.NewSecret, expiresAt: expiresAt, markOldAsRetired: retireOld);
        var plain = result.plainSecret ?? request?.NewSecret;

        try
        {
            await UpdateOpenIddictApplication(client, plaintextSecret: plain);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync rotated secret with OpenIddict for client {ClientId}", client.ClientId);
        }

        var response = new { clientId = client.ClientId, secret = plain, expiresAtUtc = result.record.ExpiresAt };
        return Ok(response);
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<ClientDto>>> GetClients(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null,
        [FromQuery] string? realmId = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var query = _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(realmId))
        {
            query = query.Where(c => c.RealmId == realmId);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(c => c.ClientId.Contains(search) || 
                                   c.Name.Contains(search) ||
                                   (c.Description != null && c.Description.Contains(search)));
        }

        var totalCount = await query.CountAsync();
        var clients = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(c => new ClientDto
            {
                Id = c.Id,
                ClientId = c.ClientId,
                Name = c.Name,
                Description = c.Description,
                IsEnabled = c.IsEnabled,
                ClientType = c.ClientType,
                AllowAuthorizationCodeFlow = c.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = c.AllowClientCredentialsFlow,
                AllowPasswordFlow = c.AllowPasswordFlow,
                AllowRefreshTokenFlow = c.AllowRefreshTokenFlow,
                RequirePkce = c.RequirePkce,
                RequireClientSecret = c.RequireClientSecret,
                AccessTokenLifetime = c.AccessTokenLifetime,
                RefreshTokenLifetime = c.RefreshTokenLifetime,
                AuthorizationCodeLifetime = c.AuthorizationCodeLifetime,
                RealmId = c.RealmId,
                RealmName = c.Realm.Name,
                CreatedAt = c.CreatedAt,
                UpdatedAt = c.UpdatedAt,
                CreatedBy = c.CreatedBy,
                UpdatedBy = c.UpdatedBy,
                RedirectUris = c.RedirectUris.Select(ru => ru.Uri).ToList(),
                PostLogoutUris = c.PostLogoutUris.Select(plu => plu.Uri).ToList(),
                Scopes = c.Scopes.Select(s => s.Scope).ToList(),
                Permissions = c.Permissions.Select(p => p.Permission).ToList(),
                Audiences = c.Audiences.Select(a => a.Audience).ToList(),
                // dynamic fields
                SessionTimeoutHours = c.SessionTimeoutHours,
                UseSlidingSessionExpiration = c.UseSlidingSessionExpiration,
                RememberMeDurationDays = c.RememberMeDurationDays,
                RequireHttpsForCookies = c.RequireHttpsForCookies,
                CookieSameSitePolicy = c.CookieSameSitePolicy,
                IdTokenLifetimeMinutes = c.IdTokenLifetimeMinutes,
                DeviceCodeLifetimeMinutes = c.DeviceCodeLifetimeMinutes,
                AccessTokenType = c.AccessTokenType,
                UseOneTimeRefreshTokens = c.UseOneTimeRefreshTokens,
                MaxRefreshTokensPerUser = c.MaxRefreshTokensPerUser,
                HashAccessTokens = c.HashAccessTokens,
                UpdateAccessTokenClaimsOnRefresh = c.UpdateAccessTokenClaimsOnRefresh,
                RequireConsent = c.RequireConsent,
                AllowRememberConsent = c.AllowRememberConsent,
                AllowAccessToUserInfoEndpoint = c.AllowAccessToUserInfoEndpoint,
                AllowAccessToIntrospectionEndpoint = c.AllowAccessToIntrospectionEndpoint,
                AllowAccessToRevocationEndpoint = c.AllowAccessToRevocationEndpoint,
                IncludeJwtId = c.IncludeJwtId,
                AlwaysSendClientClaims = c.AlwaysSendClientClaims,
                AlwaysIncludeUserClaimsInIdToken = c.AlwaysIncludeUserClaimsInIdToken,
                ClientClaimsPrefix = c.ClientClaimsPrefix,
                RequireMfa = c.RequireMfa,
                MfaGracePeriodMinutes = c.MfaGracePeriodMinutes,
                AllowedMfaMethods = c.AllowedMfaMethods,
                RememberMfaForSession = c.RememberMfaForSession,
                RateLimitRequestsPerMinute = c.RateLimitRequestsPerMinute,
                RateLimitRequestsPerHour = c.RateLimitRequestsPerHour,
                RateLimitRequestsPerDay = c.RateLimitRequestsPerDay,
                ThemeName = c.ThemeName,
                CustomCssUrl = c.CustomCssUrl,
                CustomJavaScriptUrl = c.CustomJavaScriptUrl,
                PageTitlePrefix = c.PageTitlePrefix,
                LogoUri = c.LogoUri,
                ClientUri = c.ClientUri,
                PolicyUri = c.PolicyUri,
                TosUri = c.TosUri,
                BackChannelLogoutUri = c.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = c.BackChannelLogoutSessionRequired,
                FrontChannelLogoutUri = c.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = c.FrontChannelLogoutSessionRequired,
                AllowedCorsOrigins = c.AllowedCorsOrigins,
                AllowedIdentityProviders = c.AllowedIdentityProviders,
                ProtocolType = c.ProtocolType,
                EnableDetailedErrors = c.EnableDetailedErrors,
                LogSensitiveData = c.LogSensitiveData,
                EnableLocalLogin = c.EnableLocalLogin,
                CustomLoginPageUrl = c.CustomLoginPageUrl,
                CustomLogoutPageUrl = c.CustomLogoutPageUrl,
                CustomErrorPageUrl = c.CustomErrorPageUrl,
                // login options
                AllowPasskeyLogin = c.AllowPasskeyLogin,
                AllowQrLoginQuick = c.AllowQrLoginQuick,
                AllowQrLoginSecure = c.AllowQrLoginSecure,
                AllowCodeLogin = c.AllowCodeLogin,
                // audience configuration
                AudienceMode = c.AudienceMode,
                PrimaryAudience = c.PrimaryAudience,
                IncludeAudInIdToken = c.IncludeAudInIdToken,
                RequireExplicitAudienceScope = c.RequireExplicitAudienceScope,
                RoleInclusionOverride = c.RoleInclusionOverride,
                // PAR / JAR / JARM
                ParMode = c.ParMode,
                JarMode = c.JarMode,
                JarmMode = c.JarmMode,
                RequireSignedRequestObject = c.RequireSignedRequestObject,
                AllowedRequestObjectAlgs = c.AllowedRequestObjectAlgs
            })
            .ToListAsync();

        var result = new PagedResult<ClientDto>
        {
            Items = clients,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ClientDto>> GetClient(string id)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Audiences)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.Id == id);

        if (client == null)
        {
            return NotFound($"Client with ID '{id}' not found.");
        }

        var clientDto = new ClientDto
        {
            Id = client.Id,
            ClientId = client.ClientId,
            Name = client.Name,
            Description = client.Description,
            IsEnabled = client.IsEnabled,
            ClientType = client.ClientType,
            AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
            AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            RequirePkce = client.RequirePkce,
            RequireClientSecret = client.RequireClientSecret,
            AccessTokenLifetime = client.AccessTokenLifetime,
            RefreshTokenLifetime = client.RefreshTokenLifetime,
            AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
            RealmId = client.RealmId,
            RealmName = client.Realm.Name,
            CreatedAt = client.CreatedAt,
            UpdatedAt = client.UpdatedAt,
            CreatedBy = client.CreatedBy,
            UpdatedBy = client.UpdatedBy,
            RedirectUris = client.RedirectUris.Select(ru => ru.Uri).ToList(),
            PostLogoutUris = client.PostLogoutUris.Select(plu => plu.Uri).ToList(),
            Scopes = client.Scopes.Select(s => s.Scope).ToList(),
            Permissions = client.Permissions.Select(p => p.Permission).ToList(),
            Audiences = client.Audiences.Select(a => a.Audience).ToList(),
            // dynamic fields
            SessionTimeoutHours = client.SessionTimeoutHours,
            UseSlidingSessionExpiration = client.UseSlidingSessionExpiration,
            RememberMeDurationDays = client.RememberMeDurationDays,
            RequireHttpsForCookies = client.RequireHttpsForCookies,
            CookieSameSitePolicy = client.CookieSameSitePolicy,
            IdTokenLifetimeMinutes = client.IdTokenLifetimeMinutes,
            DeviceCodeLifetimeMinutes = client.DeviceCodeLifetimeMinutes,
            AccessTokenType = client.AccessTokenType,
            UseOneTimeRefreshTokens = client.UseOneTimeRefreshTokens,
            MaxRefreshTokensPerUser = client.MaxRefreshTokensPerUser,
            HashAccessTokens = client.HashAccessTokens,
            UpdateAccessTokenClaimsOnRefresh = client.UpdateAccessTokenClaimsOnRefresh,
            RequireConsent = client.RequireConsent,
            AllowRememberConsent = client.AllowRememberConsent,
            AllowAccessToUserInfoEndpoint = client.AllowAccessToUserInfoEndpoint,
            AllowAccessToIntrospectionEndpoint = client.AllowAccessToIntrospectionEndpoint,
            AllowAccessToRevocationEndpoint = client.AllowAccessToRevocationEndpoint,
            IncludeJwtId = client.IncludeJwtId,
            AlwaysSendClientClaims = client.AlwaysSendClientClaims,
            AlwaysIncludeUserClaimsInIdToken = client.AlwaysIncludeUserClaimsInIdToken,
            ClientClaimsPrefix = client.ClientClaimsPrefix,
            RequireMfa = client.RequireMfa,
            MfaGracePeriodMinutes = client.MfaGracePeriodMinutes,
            AllowedMfaMethods = client.AllowedMfaMethods,
            RememberMfaForSession = client.RememberMfaForSession,
            RateLimitRequestsPerMinute = client.RateLimitRequestsPerMinute,
            RateLimitRequestsPerHour = client.RateLimitRequestsPerHour,
            RateLimitRequestsPerDay = client.RateLimitRequestsPerDay,
            ThemeName = client.ThemeName,
            CustomCssUrl = client.CustomCssUrl,
            CustomJavaScriptUrl = client.CustomJavaScriptUrl,
            PageTitlePrefix = client.PageTitlePrefix,
            LogoUri = client.LogoUri,
            ClientUri = client.ClientUri,
            PolicyUri = client.PolicyUri,
            TosUri = client.TosUri,
            BackChannelLogoutUri = client.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = client.BackChannelLogoutSessionRequired,
            FrontChannelLogoutUri = client.FrontChannelLogoutUri,
            FrontChannelLogoutSessionRequired = client.FrontChannelLogoutSessionRequired,
            AllowedCorsOrigins = client.AllowedCorsOrigins,
            AllowedIdentityProviders = client.AllowedIdentityProviders,
            ProtocolType = client.ProtocolType,
            EnableDetailedErrors = client.EnableDetailedErrors,
            LogSensitiveData = client.LogSensitiveData,
            EnableLocalLogin = client.EnableLocalLogin,
            CustomLoginPageUrl = client.CustomLoginPageUrl,
            CustomLogoutPageUrl = client.CustomLogoutPageUrl,
            CustomErrorPageUrl = client.CustomErrorPageUrl,
            // login options
            AllowPasskeyLogin = client.AllowPasskeyLogin,
            AllowQrLoginQuick = client.AllowQrLoginQuick,
            AllowQrLoginSecure = client.AllowQrLoginSecure,
            AllowCodeLogin = client.AllowCodeLogin,
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            RoleInclusionOverride = client.RoleInclusionOverride,
            // PAR / JAR / JARM
            ParMode = client.ParMode,
            JarMode = client.JarMode,
            JarmMode = client.JarmMode,
            RequireSignedRequestObject = client.RequireSignedRequestObject,
            AllowedRequestObjectAlgs = client.AllowedRequestObjectAlgs
        };

        return Ok(clientDto);
    }

    /// <summary>
    /// List identity provider links for a given client (by client DB id).
    /// </summary>
    [HttpGet("{id}/identity-providers")]
    public async Task<ActionResult<IEnumerable<ClientIdentityProviderDto>>> GetIdentityProviderLinksForClient(string id)
    {
        var exists = await _context.Clients.AnyAsync(c => c.Id == id);
        if (!exists) return NotFound("Client not found");

        var links = await _context.ClientIdentityProviders
            .Where(l => l.ClientId == id)
            .Include(l => l.IdentityProvider)
            .OrderBy(l => l.Order)
            .ThenBy(l => l.IdentityProvider.DisplayName ?? l.IdentityProvider.Name)
            .ToListAsync();

        var dtos = links.Select(l => new ClientIdentityProviderDto
        {
            Id = l.Id,
            ClientId = l.ClientId,
            IdentityProviderId = l.IdentityProviderId,
            DisplayNameOverride = l.DisplayNameOverride,
            IsEnabled = l.IsEnabled,
            Order = l.Order,
            OptionsJson = l.OptionsJson
        }).ToList();

        return Ok(dtos);
    }

    /// <summary>
    /// Create a link between a client (by client DB id) and an identity provider (by IdP id or name).
    /// </summary>
    [HttpPost("{id}/identity-providers/{providerId}")]
    public async Task<ActionResult<ClientIdentityProviderDto>> LinkIdentityProviderToClient(string id, string providerId, [FromBody] ClientIdentityProviderDto? dto)
    {
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == id || c.ClientId == id);
        if (client is null) return NotFound("Client not found");

        // Accept providerId as either IdentityProvider.Id or Name
        var provider = await _context.IdentityProviders.FirstOrDefaultAsync(p => p.Id == providerId || p.Name == providerId);
        if (provider is null) return NotFound("Identity provider not found");

        // Prevent duplicate link
        var exists = await _context.ClientIdentityProviders.AnyAsync(l => l.ClientId == client.Id && l.IdentityProviderId == provider.Id);
        if (exists)
        {
            return Conflict("Link already exists");
        }

        var link = new ClientIdentityProvider
        {
            Id = Guid.NewGuid().ToString(),
            ClientId = client.Id,
            IdentityProviderId = provider.Id,
            DisplayNameOverride = dto?.DisplayNameOverride,
            IsEnabled = dto?.IsEnabled ?? true,
            Order = dto?.Order,
            OptionsJson = dto?.OptionsJson,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = User.Identity?.Name,
            UpdatedBy = User.Identity?.Name
        };

        _context.ClientIdentityProviders.Add(link);
        await _context.SaveChangesAsync();

        var result = new ClientIdentityProviderDto
        {
            Id = link.Id,
            ClientId = link.ClientId,
            IdentityProviderId = link.IdentityProviderId,
            DisplayNameOverride = link.DisplayNameOverride,
            IsEnabled = link.IsEnabled,
            Order = link.Order,
            OptionsJson = link.OptionsJson
        };

        return CreatedAtAction(nameof(GetIdentityProviderLinksForClient), new { id = client.Id }, result);
    }

    /// <summary>
    /// Remove a link between a client and an identity provider by link id.
    /// </summary>
    [HttpDelete("{id}/identity-providers/{linkId}")]
    public async Task<IActionResult> UnlinkIdentityProviderFromClient(string id, string linkId)
    {
        var clientExists = await _context.Clients.AnyAsync(c => c.Id == id || c.ClientId == id);
        if (!clientExists) return NotFound("Client not found");

        var link = await _context.ClientIdentityProviders.FirstOrDefaultAsync(l => l.Id == linkId && l.ClientId == id);
        if (link is null)
        {
            // If "id" passed was ClientId (public id), try resolving client id first
            var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == id || c.ClientId == id);
            if (client is null) return NotFound("Client not found");
            link = await _context.ClientIdentityProviders.FirstOrDefaultAsync(l => l.Id == linkId && l.ClientId == client.Id);
        }
        if (link is null) return NotFound();

        _context.ClientIdentityProviders.Remove(link);
        await _context.SaveChangesAsync();
        return NoContent();
    }

    /// <summary>
    /// Export a client to JSON (no secrets/IDs). Includes assigned users by username/email for portability.
    /// </summary>
    [HttpGet("{id}/export")]
    public async Task<ActionResult<ClientExportDto>> ExportClient(string id)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .FirstOrDefaultAsync(c => c.Id == id);

        if (client == null) return NotFound();

        var export = new ClientExportDto
        {
            ClientId = client.ClientId,
            Name = client.Name,
            Description = client.Description,
            IsEnabled = client.IsEnabled,
            ClientType = client.ClientType,
            RealmName = client.Realm.Name,
            AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
            AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
            AllowPasswordFlow = client.AllowPasswordFlow,
            AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
            AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
            RequirePkce = client.RequirePkce,
            RequireClientSecret = client.RequireClientSecret,
            AccessTokenLifetime = client.AccessTokenLifetime,
            RefreshTokenLifetime = client.RefreshTokenLifetime,
            AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
            IdTokenLifetimeMinutes = client.IdTokenLifetimeMinutes,
            DeviceCodeLifetimeMinutes = client.DeviceCodeLifetimeMinutes,
            SessionTimeoutHours = client.SessionTimeoutHours,
            UseSlidingSessionExpiration = client.UseSlidingSessionExpiration,
            RememberMeDurationDays = client.RememberMeDurationDays,
            RequireHttpsForCookies = client.RequireHttpsForCookies,
            CookieSameSitePolicy = client.CookieSameSitePolicy,
            RequireConsent = client.RequireConsent,
            AllowRememberConsent = client.AllowRememberConsent,
            IncludeJwtId = client.IncludeJwtId,
            AlwaysSendClientClaims = client.AlwaysSendClientClaims,
            AlwaysIncludeUserClaimsInIdToken = client.AlwaysIncludeUserClaimsInIdToken,
            ClientClaimsPrefix = client.ClientClaimsPrefix,
            AllowAccessToUserInfoEndpoint = client.AllowAccessToUserInfoEndpoint,
            AllowAccessToIntrospectionEndpoint = client.AllowAccessToIntrospectionEndpoint,
            AllowAccessToRevocationEndpoint = client.AllowAccessToRevocationEndpoint,
            RateLimitRequestsPerMinute = client.RateLimitRequestsPerMinute,
            RateLimitRequestsPerHour = client.RateLimitRequestsPerHour,
            RateLimitRequestsPerDay = client.RateLimitRequestsPerDay,
            ThemeName = client.ThemeName,
            CustomCssUrl = client.CustomCssUrl,
            CustomJavaScriptUrl = client.CustomJavaScriptUrl,
            PageTitlePrefix = client.PageTitlePrefix,
            LogoUri = client.LogoUri,
            ClientUri = client.ClientUri,
            PolicyUri = client.PolicyUri,
            TosUri = client.TosUri,
            BackChannelLogoutUri = client.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = client.BackChannelLogoutSessionRequired,
            FrontChannelLogoutUri = client.FrontChannelLogoutUri,
            FrontChannelLogoutSessionRequired = client.FrontChannelLogoutSessionRequired,
            AllowedCorsOrigins = client.AllowedCorsOrigins,
            AllowedIdentityProviders = client.AllowedIdentityProviders,
            ProtocolType = client.ProtocolType,
            EnableDetailedErrors = client.EnableDetailedErrors,
            LogSensitiveData = client.LogSensitiveData,
            EnableLocalLogin = client.EnableLocalLogin,
            CustomLoginPageUrl = client.CustomLoginPageUrl,
            CustomLogoutPageUrl = client.CustomLogoutPageUrl,
            CustomErrorPageUrl = client.CustomErrorPageUrl,
            AllowPasskeyLogin = client.AllowPasskeyLogin,
            AllowQrLoginQuick = client.AllowQrLoginQuick,
            AllowQrLoginSecure = client.AllowQrLoginSecure,
            AllowCodeLogin = client.AllowCodeLogin,
            RedirectUris = client.RedirectUris.Select(x => x.Uri).ToList(),
            PostLogoutUris = client.PostLogoutUris.Select(x => x.Uri).ToList(),
            Scopes = client.Scopes.Select(x => x.Scope).ToList(),
            Permissions = client.Permissions.Select(x => x.Permission).ToList(),
            Audiences = client.Audiences.Select(a => a.Audience).ToList(),
            AudienceMode = client.AudienceMode,
            PrimaryAudience = client.PrimaryAudience,
            IncludeAudInIdToken = client.IncludeAudInIdToken,
            RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
            RoleInclusionOverride = client.RoleInclusionOverride,
            ParMode = client.ParMode,
            // JAR/JARM
            JarMode = client.JarMode,
            JarmMode = client.JarmMode,
            RequireSignedRequestObject = client.RequireSignedRequestObject,
            AllowedRequestObjectAlgs = client.AllowedRequestObjectAlgs
        };
        // Assigned users (by username/email only)
        var assignedUsers = await _context.ClientUsers
            .Where(cu => cu.ClientId == client.Id)
            .Join(_context.Users, cu => cu.UserId, u => u.Id, (cu, u) => new { u.UserName, u.Email })
            .ToListAsync();
        export.AssignedUsers = assignedUsers
            .Select(x => new ClientAssignedUserRef { UserName = x.UserName, Email = x.Email })
            .ToList();
        return Ok(export);
    }

    /// <summary>
    /// Import a client from JSON (upsert using ClientId and RealmName). Includes applying assigned users if provided.
    /// </summary>
    [HttpPost("import")]
    public async Task<ActionResult<ClientImportResult>> ImportClient([FromBody] ClientExportDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.ClientId) || string.IsNullOrWhiteSpace(dto.RealmName))
        {
            return ValidationProblem("ClientId and RealmName are required");
        }

        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == dto.RealmName);
        if (realm == null)
        {
            return NotFound($"Realm '{dto.RealmName}' not found. Import the realm first.");
        }

        string? generatedSecret = null;

        var strategy = _context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            using var tx = await _context.Database.BeginTransactionAsync();
            try
            {
                var client = await _context.Clients
                    .Include(c => c.RedirectUris)
                    .Include(c => c.PostLogoutUris)
                    .Include(c => c.Scopes)
                    .Include(c => c.Permissions)
                    .Include(c => c.Audiences)
                    .FirstOrDefaultAsync(c => c.ClientId == dto.ClientId && c.RealmId == realm.Id);

                var now = DateTime.UtcNow;
                var userName = User?.Identity?.Name;

                var requiresSecret = (dto.ClientType == ClientType.Confidential || dto.ClientType == ClientType.Machine) && dto.RequireClientSecret;

                if (client == null)
                {
                    client = new Client
                    {
                        ClientId = dto.ClientId,
                        RealmId = realm.Id,
                        CreatedAt = now,
                        UpdatedAt = now,
                        CreatedBy = userName,
                        UpdatedBy = userName
                    };
                    _context.Clients.Add(client);

                    // If confidential and requires secret, generate one
                    if (requiresSecret)
                    {
                        generatedSecret = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
                        // Use redaction marker in entity; actual hash recorded below after SaveChanges
                        client.ClientSecret = "{HASHED}";
                    }
                }

                // Update simple props
                client.Name = dto.Name;
                client.Description = dto.Description;
                client.IsEnabled = dto.IsEnabled;
                client.ClientType = dto.ClientType;
                client.AllowAuthorizationCodeFlow = dto.AllowAuthorizationCodeFlow;
                client.AllowClientCredentialsFlow = dto.AllowClientCredentialsFlow;
                client.AllowPasswordFlow = dto.AllowPasswordFlow;
                client.AllowRefreshTokenFlow = dto.AllowRefreshTokenFlow;
                client.AllowDeviceCodeFlow = dto.AllowDeviceCodeFlow;
                client.RequirePkce = dto.RequirePkce;
                client.RequireClientSecret = dto.RequireClientSecret;
                client.AccessTokenLifetime = dto.AccessTokenLifetime;
                client.RefreshTokenLifetime = dto.RefreshTokenLifetime;
                client.AuthorizationCodeLifetime = dto.AuthorizationCodeLifetime;
                client.IdTokenLifetimeMinutes = dto.IdTokenLifetimeMinutes;
                client.DeviceCodeLifetimeMinutes = dto.DeviceCodeLifetimeMinutes;
                // PAR / JAR / JARM
                client.ParMode = dto.ParMode;
                client.JarMode = dto.JarMode;
                client.JarmMode = dto.JarmMode;
                client.RequireSignedRequestObject = dto.RequireSignedRequestObject;
                client.AllowedRequestObjectAlgs = dto.AllowedRequestObjectAlgs;

                client.SessionTimeoutHours = dto.SessionTimeoutHours;
                client.UseSlidingSessionExpiration = dto.UseSlidingSessionExpiration;
                client.RememberMeDurationDays = dto.RememberMeDurationDays;
                client.RequireHttpsForCookies = dto.RequireHttpsForCookies;
                client.CookieSameSitePolicy = dto.CookieSameSitePolicy;
                client.RequireConsent = dto.RequireConsent;
                client.AllowRememberConsent = dto.AllowRememberConsent;
                client.IncludeJwtId = dto.IncludeJwtId;
                client.AlwaysSendClientClaims = dto.AlwaysSendClientClaims;
                client.AlwaysIncludeUserClaimsInIdToken = dto.AlwaysIncludeUserClaimsInIdToken;
                client.ClientClaimsPrefix = dto.ClientClaimsPrefix;
                client.AllowAccessToUserInfoEndpoint = dto.AllowAccessToUserInfoEndpoint;
                client.AllowAccessToIntrospectionEndpoint = dto.AllowAccessToIntrospectionEndpoint;
                client.AllowAccessToRevocationEndpoint = dto.AllowAccessToRevocationEndpoint;
                client.RateLimitRequestsPerMinute = dto.RateLimitRequestsPerMinute;
                client.RateLimitRequestsPerHour = dto.RateLimitRequestsPerHour;
                client.RateLimitRequestsPerDay = dto.RateLimitRequestsPerDay;
                client.ThemeName = dto.ThemeName;
                client.CustomCssUrl = dto.CustomCssUrl;
                client.CustomJavaScriptUrl = dto.CustomJavaScriptUrl;
                client.PageTitlePrefix = dto.PageTitlePrefix;
                client.LogoUri = dto.LogoUri;
                client.ClientUri = dto.ClientUri;
                client.PolicyUri = dto.PolicyUri;
                client.TosUri = dto.TosUri;
                client.BackChannelLogoutUri = dto.BackChannelLogoutUri;
                client.BackChannelLogoutSessionRequired = dto.BackChannelLogoutSessionRequired;
                client.FrontChannelLogoutUri = dto.FrontChannelLogoutUri;
                client.FrontChannelLogoutSessionRequired = dto.FrontChannelLogoutSessionRequired;
                client.AllowedCorsOrigins = dto.AllowedCorsOrigins;
                client.AllowedIdentityProviders = dto.AllowedIdentityProviders;
                client.ProtocolType = dto.ProtocolType;
                client.EnableDetailedErrors = dto.EnableDetailedErrors;
                client.LogSensitiveData = dto.LogSensitiveData;
                client.EnableLocalLogin = dto.EnableLocalLogin;
                client.CustomLoginPageUrl = dto.CustomLoginPageUrl;
                client.CustomLogoutPageUrl = dto.CustomLogoutPageUrl;
                client.CustomErrorPageUrl = dto.CustomErrorPageUrl;

                // login options
                client.AllowPasskeyLogin = dto.AllowPasskeyLogin;
                client.AllowQrLoginQuick = dto.AllowQrLoginQuick;
                client.AllowQrLoginSecure = dto.AllowQrLoginSecure;
                client.AllowCodeLogin = dto.AllowCodeLogin;

                // Update audience configuration
                client.AudienceMode = dto.AudienceMode;
                client.PrimaryAudience = dto.PrimaryAudience;
                client.IncludeAudInIdToken = dto.IncludeAudInIdToken;
                client.RequireExplicitAudienceScope = dto.RequireExplicitAudienceScope;
                client.RoleInclusionOverride = dto.RoleInclusionOverride;

                client.UpdatedAt = now;
                client.UpdatedBy = userName;

                // Update collections: replace existing
                _context.ClientRedirectUris.RemoveRange(client.RedirectUris);
                foreach (var uri in dto.RedirectUris.Distinct())
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = client.Id, Uri = uri });
                }

                _context.ClientPostLogoutUris.RemoveRange(client.PostLogoutUris);
                foreach (var uri in dto.PostLogoutUris.Distinct())
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = client.Id, Uri = uri });
                }

                _context.ClientScopes.RemoveRange(client.Scopes);
                foreach (var s in dto.Scopes.Distinct())
                {
                    _context.ClientScopes.Add(new ClientScope { ClientId = client.Id, Scope = s });
                }

                _context.ClientPermissions.RemoveRange(client.Permissions);
                foreach (var p in dto.Permissions.Distinct())
                {
                    _context.ClientPermissions.Add(new ClientPermission { ClientId = client.Id, Permission = p });
                }

                // Update audiences
                _context.ClientAudiences.RemoveRange(client.Audiences);
                foreach (var a in dto.Audiences.Distinct())
                {
                    _context.ClientAudiences.Add(new ClientAudience { ClientId = client.Id, Audience = a });
                }

                await _context.SaveChangesAsync();

                // If we generated a secret for this import, create a history record now
                if (requiresSecret && !string.IsNullOrWhiteSpace(generatedSecret))
                {
                    await _clientSecretService.SetNewSecretAsync(client.Id, providedPlaintext: generatedSecret);
                }

                await tx.CommitAsync();

                // Reload full client with related data for returning DTO
                var full = await _context.Clients
                    .Include(c => c.Realm)
                    .Include(c => c.RedirectUris)
                    .Include(c => c.PostLogoutUris)
                    .Include(c => c.Scopes)
                    .Include(c => c.Permissions)
                    .Include(c => c.Audiences)
                    .FirstOrDefaultAsync(c => c.Id == client.Id);

                var clientDto = new ClientDto
                {
                    Id = full!.Id,
                    ClientId = full.ClientId,
                    Name = full.Name,
                    Description = full.Description,
                    IsEnabled = full.IsEnabled,
                    ClientType = full.ClientType,
                    AllowAuthorizationCodeFlow = full.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = full.AllowClientCredentialsFlow,
                    AllowPasswordFlow = full.AllowPasswordFlow,
                    AllowRefreshTokenFlow = full.AllowRefreshTokenFlow,
                    AllowDeviceCodeFlow = full.AllowDeviceCodeFlow,
                    RequirePkce = full.RequirePkce,
                    RequireClientSecret = full.RequireClientSecret,
                    AccessTokenLifetime = full.AccessTokenLifetime,
                    RefreshTokenLifetime = full.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = full.AuthorizationCodeLifetime,
                    RealmId = full.RealmId,
                    RealmName = full.Realm.Name,
                    CreatedAt = full.CreatedAt,
                    UpdatedAt = full.UpdatedAt,
                    CreatedBy = full.CreatedBy,
                    UpdatedBy = full.UpdatedBy,
                    RedirectUris = full.RedirectUris.Select(ru => ru.Uri).ToList(),
                    PostLogoutUris = full.PostLogoutUris.Select(plu => plu.Uri).ToList(),
                    Scopes = full.Scopes.Select(s => s.Scope).ToList(),
                    Permissions = full.Permissions.Select(p => p.Permission).ToList(),
                    Audiences = full.Audiences.Select(a => a.Audience).ToList(),
                    // dynamic fields
                    SessionTimeoutHours = full.SessionTimeoutHours,
                    UseSlidingSessionExpiration = full.UseSlidingSessionExpiration,
                    RememberMeDurationDays = full.RememberMeDurationDays,
                    RequireHttpsForCookies = full.RequireHttpsForCookies,
                    CookieSameSitePolicy = full.CookieSameSitePolicy,
                    IdTokenLifetimeMinutes = full.IdTokenLifetimeMinutes,
                    DeviceCodeLifetimeMinutes = full.DeviceCodeLifetimeMinutes,
                    AccessTokenType = full.AccessTokenType,
                    UseOneTimeRefreshTokens = full.UseOneTimeRefreshTokens,
                    MaxRefreshTokensPerUser = full.MaxRefreshTokensPerUser,
                    HashAccessTokens = full.HashAccessTokens,
                    UpdateAccessTokenClaimsOnRefresh = full.UpdateAccessTokenClaimsOnRefresh,
                    RequireConsent = full.RequireConsent,
                    AllowRememberConsent = full.AllowRememberConsent,
                    AllowAccessToUserInfoEndpoint = full.AllowAccessToUserInfoEndpoint,
                    AllowAccessToIntrospectionEndpoint = full.AllowAccessToIntrospectionEndpoint,
                    AllowAccessToRevocationEndpoint = full.AllowAccessToRevocationEndpoint,
                    IncludeJwtId = full.IncludeJwtId,
                    AlwaysSendClientClaims = full.AlwaysSendClientClaims,
                    AlwaysIncludeUserClaimsInIdToken = full.AlwaysIncludeUserClaimsInIdToken,
                    ClientClaimsPrefix = full.ClientClaimsPrefix,
                    RequireMfa = full.RequireMfa,
                    MfaGracePeriodMinutes = full.MfaGracePeriodMinutes,
                    AllowedMfaMethods = full.AllowedMfaMethods,
                    RememberMfaForSession = full.RememberMfaForSession,
                    RateLimitRequestsPerMinute = full.RateLimitRequestsPerMinute,
                    RateLimitRequestsPerHour = full.RateLimitRequestsPerHour,
                    RateLimitRequestsPerDay = full.RateLimitRequestsPerDay,
                    ThemeName = full.ThemeName,
                    CustomCssUrl = full.CustomCssUrl,
                    CustomJavaScriptUrl = full.CustomJavaScriptUrl,
                    PageTitlePrefix = full.PageTitlePrefix,
                    LogoUri = full.LogoUri,
                    ClientUri = full.ClientUri,
                    PolicyUri = full.PolicyUri,
                    TosUri = full.TosUri,
                    BackChannelLogoutUri = full.BackChannelLogoutUri,
                    BackChannelLogoutSessionRequired = full.BackChannelLogoutSessionRequired,
                    FrontChannelLogoutUri = full.FrontChannelLogoutUri,
                    FrontChannelLogoutSessionRequired = full.FrontChannelLogoutSessionRequired,
                    AllowedCorsOrigins = full.AllowedCorsOrigins,
                    AllowedIdentityProviders = full.AllowedIdentityProviders,
                    ProtocolType = full.ProtocolType,
                    EnableDetailedErrors = full.EnableDetailedErrors,
                    LogSensitiveData = full.LogSensitiveData,
                    EnableLocalLogin = full.EnableLocalLogin,
                    CustomLoginPageUrl = full.CustomLoginPageUrl,
                    CustomLogoutPageUrl = full.CustomLogoutPageUrl,
                    CustomErrorPageUrl = full.CustomErrorPageUrl,
                    // login options
                    AllowPasskeyLogin = full.AllowPasskeyLogin,
                    AllowQrLoginQuick = full.AllowQrLoginQuick,
                    AllowQrLoginSecure = full.AllowQrLoginSecure,
                    AllowCodeLogin = full.AllowCodeLogin,
                    // PAR / JAR / JARM
                    ParMode = full.ParMode,
                    JarMode = full.JarMode,
                    JarmMode = full.JarmMode,
                    RequireSignedRequestObject = full.RequireSignedRequestObject,
                    AllowedRequestObjectAlgs = full.AllowedRequestObjectAlgs
                };

                var result = new ClientImportResult
                {
                    Client = clientDto,
                    GeneratedClientSecret = generatedSecret
                };

                return Ok(result);
            }
            catch (Exception ex)
            {
                await tx.RollbackAsync();
                _logger.LogError(ex, "Failed to import client {ClientId}", dto.ClientId);
                return Problem(title: "Failed to import client", detail: ex.Message);
            }
        });
    }

    [HttpPost]
    public async Task<ActionResult<ClientDto>> CreateClient([FromBody] CreateClientRequest request)
    {
        // Generate default ID when missing
        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            request.ClientId = GenerateClientIdFromName(request.Name);
        }

        // Verify realm exists
        var realm = await _context.Realms.FindAsync(request.RealmId);
        if (realm == null)
        {
            return BadRequest($"Realm with ID '{request.RealmId}' not found.");
        }

        // Check if client ID is unique
        if (await _context.Clients.AnyAsync(c => c.ClientId == request.ClientId))
        {
            return BadRequest($"Client with ID '{request.ClientId}' already exists.");
        }

        // Validate confidential/machine secret requirement
        var requiresSecret = (request.ClientType == ClientType.Confidential || request.ClientType == ClientType.Machine) && request.RequireClientSecret;
        if (requiresSecret && string.IsNullOrWhiteSpace(request.ClientSecret))
        {
            return ValidationProblem("ClientSecret is required for confidential or machine clients when RequireClientSecret is true.");
        }

        var strategy = _context.Database.CreateExecutionStrategy();
        var result = await strategy.ExecuteAsync(async () =>
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var client = new Client
                {
                    ClientId = request.ClientId,
                    // Do NOT store plaintext; use redaction marker to avoid leakage
                    ClientSecret = requiresSecret ? "{HASHED}" : null,
                    Name = request.Name,
                    Description = request.Description,
                    RealmId = request.RealmId,
                    IsEnabled = request.IsEnabled,
                    ClientType = request.ClientType, // shared enum
                    AllowAuthorizationCodeFlow = request.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = request.AllowClientCredentialsFlow,
                    AllowPasswordFlow = request.AllowPasswordFlow,
                    AllowRefreshTokenFlow = request.AllowRefreshTokenFlow,
                    AllowDeviceCodeFlow = request.AllowDeviceCodeFlow,
                    RequirePkce = request.RequirePkce,
                    RequireClientSecret = request.RequireClientSecret,
                    AccessTokenLifetime = request.AccessTokenLifetime ?? MrWhoConstants.TokenLifetimes.AccessToken,
                    RefreshTokenLifetime = request.RefreshTokenLifetime ?? MrWhoConstants.TokenLifetimes.RefreshToken,
                    AuthorizationCodeLifetime = request.AuthorizationCodeLifetime ?? MrWhoConstants.TokenLifetimes.AuthorizationCode,
                    CreatedBy = User.Identity?.Name,

                    // login options
                    AllowPasskeyLogin = request.AllowPasskeyLogin,
                    AllowQrLoginQuick = request.AllowQrLoginQuick,
                    AllowQrLoginSecure = request.AllowQrLoginSecure,
                    AllowCodeLogin = request.AllowCodeLogin,

                    // audience configuration
                    AudienceMode = request.AudienceMode,
                    PrimaryAudience = request.PrimaryAudience,
                    IncludeAudInIdToken = request.IncludeAudInIdToken,
                    RequireExplicitAudienceScope = request.RequireExplicitAudienceScope,
                    RoleInclusionOverride = request.RoleInclusionOverride,

                    // PAR / JAR / JARM
                    ParMode = request.ParMode,
                    JarMode = request.JarMode,
                    JarmMode = request.JarmMode,
                    RequireSignedRequestObject = request.RequireSignedRequestObject,
                    AllowedRequestObjectAlgs = request.AllowedRequestObjectAlgs
                };

                _context.Clients.Add(client);
                await _context.SaveChangesAsync();

                // Add redirect URIs
                foreach (var uri in request.RedirectUris)
                {
                    _context.ClientRedirectUris.Add(new ClientRedirectUri
                    {
                        ClientId = client.Id,
                        Uri = uri
                    });
                }

                // Add post-logout URIs
                foreach (var uri in request.PostLogoutUris)
                {
                    _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                    {
                        ClientId = client.Id,
                        Uri = uri
                    });
                }

                // Add scopes
                foreach (var scope in request.Scopes)
                {
                    _context.ClientScopes.Add(new ClientScope
                    {
                        ClientId = client.Id,
                        Scope = scope
                    });
                }

                // Add permissions
                foreach (var permission in request.Permissions)
                {
                    _context.ClientPermissions.Add(new ClientPermission
                    {
                        ClientId = client.Id,
                        Permission = permission
                    });
                }

                // Add audiences
                foreach (var audience in request.Audiences)
                {
                    _context.ClientAudiences.Add(new ClientAudience
                    {
                        ClientId = client.Id,
                        Audience = audience
                    });
                }

                await _context.SaveChangesAsync();

                // Hash and record secret only after client exists in DB
                if (requiresSecret && !string.IsNullOrWhiteSpace(request.ClientSecret))
                {
                    await _clientSecretService.SetNewSecretAsync(client.Id, providedPlaintext: request.ClientSecret);
                }
                
                // Create OpenIddict application only if valid
                if (!requiresSecret || !string.IsNullOrWhiteSpace(request.ClientSecret))
                {
                    await CreateOpenIddictApplication(client, request);
                }
                else
                {
                    _logger.LogWarning("Skipping OpenIddict application creation for client '{ClientId}' due to missing secret for confidential/machine client.", client.ClientId);
                }

                await transaction.CommitAsync();

                _logger.LogInformation("Client '{ClientId}' created successfully with ID {Id}", client.ClientId, client.Id);

                var clientDto = new ClientDto
                {
                    Id = client.Id,
                    ClientId = client.ClientId,
                    Name = client.Name,
                    Description = client.Description,
                    IsEnabled = client.IsEnabled,
                    ClientType = client.ClientType,
                    AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
                    AllowPasswordFlow = client.AllowPasswordFlow,
                    AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
                    AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
                    RequirePkce = client.RequirePkce,
                    RequireClientSecret = client.RequireClientSecret,
                    AccessTokenLifetime = client.AccessTokenLifetime,
                    RefreshTokenLifetime = client.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
                    RealmId = client.RealmId,
                    RealmName = realm.Name,
                    CreatedAt = client.CreatedAt,
                    UpdatedAt = client.UpdatedAt,
                    CreatedBy = client.CreatedBy,
                    UpdatedBy = client.UpdatedBy,
                    RedirectUris = request.RedirectUris,
                    PostLogoutUris = request.PostLogoutUris,
                    Scopes = request.Scopes,
                    Permissions = request.Permissions,
                    Audiences = request.Audiences,
                    AudienceMode = client.AudienceMode,
                    PrimaryAudience = client.PrimaryAudience,
                    IncludeAudInIdToken = client.IncludeAudInIdToken,
                    RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
                    RoleInclusionOverride = client.RoleInclusionOverride,
                    // login options
                    AllowPasskeyLogin = client.AllowPasskeyLogin,
                    AllowQrLoginQuick = client.AllowQrLoginQuick,
                    AllowQrLoginSecure = client.AllowQrLoginSecure,
                    AllowCodeLogin = client.AllowCodeLogin,
                    // PAR / JAR / JARM
                    ParMode = client.ParMode,
                    JarMode = client.JarMode,
                    JarmMode = client.JarmMode,
                    RequireSignedRequestObject = client.RequireSignedRequestObject,
                    AllowedRequestObjectAlgs = client.AllowedRequestObjectAlgs
                };

                return CreatedAtAction(nameof(GetClient), new { id = client.Id }, clientDto);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error creating client '{ClientId}'", request.ClientId);
                throw;
            }
        });

        return result;
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ClientDto>> UpdateClient(string id, [FromBody] UpdateClientRequest request)
    {
        var client = await _context.Clients
            .Include(c => c.Realm)
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Include(c => c.Audiences)
            .FirstOrDefaultAsync(c => c.Id == id);

        if (client == null)
        {
            return NotFound($"Client with ID '{id}' not found.");
        }

        // validate secret requirement before persisting/creating openiddict app
        var targetType = request.ClientType ?? client.ClientType;
        var requireSecret = (targetType == ClientType.Confidential || targetType == ClientType.Machine) && (request.RequireClientSecret ?? client.RequireClientSecret);

        // Allow update without re-entering secret if an active (non-expired) secret exists in history
        var hasActiveSecret = await _context.ClientSecretHistories
            .AnyAsync(h => h.ClientId == client.Id && h.Status == ClientSecretStatus.Active && (h.ExpiresAt == null || h.ExpiresAt > DateTime.UtcNow));

        if (requireSecret && string.IsNullOrWhiteSpace(request.ClientSecret) && !hasActiveSecret)
        {
            return ValidationProblem("ClientSecret is required for confidential or machine clients when no active secret exists. Provide it once or rotate the secret.");
        }

        // Use execution strategy for transaction handling with retry support
        var strategy = _context.Database.CreateExecutionStrategy();
        var result = await strategy.ExecuteAsync(async () =>
        {
            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // Update basic properties
                // Do NOT assign plaintext secret directly; handle rotation later
                if (!string.IsNullOrEmpty(request.Name))
                    client.Name = request.Name;
                client.Description = request.Description;
                if (request.IsEnabled.HasValue)
                    client.IsEnabled = request.IsEnabled.Value;
                if (request.ClientType.HasValue)
                    client.ClientType = request.ClientType.Value; // shared enum
                if (request.AllowAuthorizationCodeFlow.HasValue)
                    client.AllowAuthorizationCodeFlow = request.AllowAuthorizationCodeFlow.Value;
                if (request.AllowClientCredentialsFlow.HasValue)
                    client.AllowClientCredentialsFlow = request.AllowClientCredentialsFlow.Value;
                if (request.AllowPasswordFlow.HasValue)
                    client.AllowPasswordFlow = request.AllowPasswordFlow.Value;
                if (request.AllowRefreshTokenFlow.HasValue)
                    client.AllowRefreshTokenFlow = request.AllowRefreshTokenFlow.Value;
                if (request.AllowDeviceCodeFlow.HasValue)
                    client.AllowDeviceCodeFlow = request.AllowDeviceCodeFlow.Value;
                if (request.RequirePkce.HasValue)
                    client.RequirePkce = request.RequirePkce.Value;
                if (request.RequireClientSecret.HasValue)
                    client.RequireClientSecret = request.RequireClientSecret.Value;

                client.AccessTokenLifetime = request.AccessTokenLifetime ?? client.AccessTokenLifetime;
                client.RefreshTokenLifetime = request.RefreshTokenLifetime ?? client.RefreshTokenLifetime;
                client.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime ?? client.AuthorizationCodeLifetime;

                // === Apply dynamic configuration (allow setting to null to reset to defaults) ===
                client.SessionTimeoutHours = request.SessionTimeoutHours;
                client.UseSlidingSessionExpiration = request.UseSlidingSessionExpiration;
                client.RememberMeDurationDays = request.RememberMeDurationDays;
                client.RequireHttpsForCookies = request.RequireHttpsForCookies;
                client.CookieSameSitePolicy = request.CookieSameSitePolicy;

                client.IdTokenLifetimeMinutes = request.IdTokenLifetimeMinutes;
                client.DeviceCodeLifetimeMinutes = request.DeviceCodeLifetimeMinutes;
                client.AccessTokenType = request.AccessTokenType;
                client.UseOneTimeRefreshTokens = request.UseOneTimeRefreshTokens;
                client.MaxRefreshTokensPerUser = request.MaxRefreshTokensPerUser;
                client.HashAccessTokens = request.HashAccessTokens;
                client.UpdateAccessTokenClaimsOnRefresh = request.UpdateAccessTokenClaimsOnRefresh;

                client.RequireConsent = request.RequireConsent;
                client.AllowRememberConsent = request.AllowRememberConsent;
                client.AllowAccessToUserInfoEndpoint = request.AllowAccessToUserInfoEndpoint;
                client.AllowAccessToIntrospectionEndpoint = request.AllowAccessToIntrospectionEndpoint;
                client.AllowAccessToRevocationEndpoint = request.AllowAccessToRevocationEndpoint;
                client.IncludeJwtId = request.IncludeJwtId;
                client.AlwaysSendClientClaims = request.AlwaysSendClientClaims;
                client.AlwaysIncludeUserClaimsInIdToken = request.AlwaysIncludeUserClaimsInIdToken;
                client.ClientClaimsPrefix = request.ClientClaimsPrefix;

                client.RequireMfa = request.RequireMfa;
                client.MfaGracePeriodMinutes = request.MfaGracePeriodMinutes;
                client.AllowedMfaMethods = request.AllowedMfaMethods;
                client.RememberMfaForSession = request.RememberMfaForSession;

                client.RateLimitRequestsPerMinute = request.RateLimitRequestsPerMinute;
                client.RateLimitRequestsPerHour = request.RateLimitRequestsPerHour;
                client.RateLimitRequestsPerDay = request.RateLimitRequestsPerDay;

                client.ThemeName = request.ThemeName;
                client.CustomCssUrl = request.CustomCssUrl;
                client.CustomJavaScriptUrl = request.CustomJavaScriptUrl;
                client.PageTitlePrefix = request.PageTitlePrefix;
                client.LogoUri = request.LogoUri;
                client.ClientUri = request.ClientUri;
                client.PolicyUri = request.PolicyUri;
                client.TosUri = request.TosUri;

                client.BackChannelLogoutUri = request.BackChannelLogoutUri;
                client.BackChannelLogoutSessionRequired = request.BackChannelLogoutSessionRequired;
                client.FrontChannelLogoutUri = request.FrontChannelLogoutUri;
                client.FrontChannelLogoutSessionRequired = request.FrontChannelLogoutSessionRequired;

                client.AllowedCorsOrigins = request.AllowedCorsOrigins;
                client.AllowedIdentityProviders = request.AllowedIdentityProviders;

                client.ProtocolType = request.ProtocolType;
                client.EnableDetailedErrors = request.EnableDetailedErrors;
                client.LogSensitiveData = request.LogSensitiveData;
                client.EnableLocalLogin = request.EnableLocalLogin;

                client.CustomLoginPageUrl = request.CustomLoginPageUrl;
                client.CustomLogoutPageUrl = request.CustomLogoutPageUrl;
                client.CustomErrorPageUrl = request.CustomErrorPageUrl;

                // PAR / JAR / JARM
                client.ParMode = request.ParMode;
                if (request.JarMode.HasValue) client.JarMode = request.JarMode;
                if (request.JarmMode.HasValue) client.JarmMode = request.JarmMode;
                if (request.RequireSignedRequestObject.HasValue) client.RequireSignedRequestObject = request.RequireSignedRequestObject;
                if (request.AllowedRequestObjectAlgs != null) client.AllowedRequestObjectAlgs = request.AllowedRequestObjectAlgs;

                // Update redirect URIs if provided
                if (request.RedirectUris != null)
                {
                    _context.ClientRedirectUris.RemoveRange(client.RedirectUris);
                    foreach (var uri in request.RedirectUris)
                    {
                        _context.ClientRedirectUris.Add(new ClientRedirectUri
                        {
                            ClientId = client.Id,
                            Uri = uri
                        });
                    }
                }

                // Update post-logout URIs if provided
                if (request.PostLogoutUris != null)
                {
                    _context.ClientPostLogoutUris.RemoveRange(client.PostLogoutUris);
                    foreach (var uri in request.PostLogoutUris)
                    {
                        _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri
                        {
                            ClientId = client.Id,
                            Uri = uri
                        });
                    }
                }

                // Update scopes if provided
                if (request.Scopes != null)
                {
                    _context.ClientScopes.RemoveRange(client.Scopes);
                    foreach (var scope in request.Scopes)
                    {
                        _context.ClientScopes.Add(new ClientScope
                        {
                            ClientId = client.Id,
                            Scope = scope
                        });
                    }
                }

                // Update permissions if provided
                if (request.Permissions != null)
                {
                    _context.ClientPermissions.RemoveRange(client.Permissions);
                    foreach (var permission in request.Permissions)
                    {
                        _context.ClientPermissions.Add(new ClientPermission
                        {
                            ClientId = client.Id,
                            Permission = permission
                        });
                    }
                }

                // Update audiences if provided
                if (request.Audiences != null)
                {
                    _context.ClientAudiences.RemoveRange(client.Audiences);
                    foreach (var audience in request.Audiences)
                    {
                        _context.ClientAudiences.Add(new ClientAudience
                        {
                            ClientId = client.Id,
                            Audience = audience
                        });
                    }
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Client '{ClientId}' updated in database", client.ClientId);

                // Rotate secret if a new one is provided
                if (!string.IsNullOrWhiteSpace(request.ClientSecret))
                {
                    // Ensure redaction marker on the entity and create history record
                    await _clientSecretService.SetNewSecretAsync(client.Id, providedPlaintext: request.ClientSecret);
                }
                
                await transaction.CommitAsync();

                // Try syncing OpenIddict after committing DB changes so DB update never rolls back due to sync issues
                try
                {
                    await UpdateOpenIddictApplication(client, request.ClientSecret);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "OpenIddict sync failed for client '{ClientId}'. DB changes were committed.", client.ClientId);
                }

                _logger.LogInformation("Client '{ClientId}' updated successfully", client.ClientId);
                
                // Reload client with updated data
                await _context.Entry(client).ReloadAsync();
                await _context.Entry(client).Reference(c => c.Realm).LoadAsync();
                await _context.Entry(client).Collection(c => c.RedirectUris).LoadAsync();
                await _context.Entry(client).Collection(c => c.PostLogoutUris).LoadAsync();
                await _context.Entry(client).Collection(c => c.Scopes).LoadAsync();
                await _context.Entry(client).Collection(c => c.Permissions).LoadAsync();
                await _context.Entry(client).Collection(c => c.Audiences).LoadAsync();
                
                var clientDto = new ClientDto
                {
                    Id = client.Id,
                    ClientId = client.ClientId,
                    Name = client.Name,
                    Description = client.Description,
                    IsEnabled = client.IsEnabled,
                    ClientType = client.ClientType, // shared enum
                    AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
                    AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
                    AllowPasswordFlow = client.AllowPasswordFlow,
                    AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
                    AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
                    RequirePkce = client.RequirePkce,
                    RequireClientSecret = client.RequireClientSecret,
                    AccessTokenLifetime = client.AccessTokenLifetime,
                    RefreshTokenLifetime = client.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = client.AuthorizationCodeLifetime,
                    RealmId = client.RealmId,
                    RealmName = client.Realm.Name,
                    CreatedAt = client.CreatedAt,
                    UpdatedAt = client.UpdatedAt,
                    CreatedBy = client.CreatedBy,
                    UpdatedBy = client.UpdatedBy,
                    RedirectUris = client.RedirectUris.Select(ru => ru.Uri).ToList(),
                    PostLogoutUris = client.PostLogoutUris.Select(plu => plu.Uri).ToList(),
                    Scopes = client.Scopes.Select(s => s.Scope).ToList(),
                    Permissions = client.Permissions.Select(p => p.Permission).ToList(),
                    Audiences = client.Audiences.Select(a => a.Audience).ToList(),

                    // dynamic fields
                    SessionTimeoutHours = client.SessionTimeoutHours,
                    UseSlidingSessionExpiration = client.UseSlidingSessionExpiration,
                    RememberMeDurationDays = client.RememberMeDurationDays,
                    RequireHttpsForCookies = client.RequireHttpsForCookies,
                    CookieSameSitePolicy = client.CookieSameSitePolicy,
                    IdTokenLifetimeMinutes = client.IdTokenLifetimeMinutes,
                    DeviceCodeLifetimeMinutes = client.DeviceCodeLifetimeMinutes,
                    AccessTokenType = client.AccessTokenType,
                    UseOneTimeRefreshTokens = client.UseOneTimeRefreshTokens,
                    MaxRefreshTokensPerUser = client.MaxRefreshTokensPerUser,
                    HashAccessTokens = client.HashAccessTokens,
                    UpdateAccessTokenClaimsOnRefresh = client.UpdateAccessTokenClaimsOnRefresh,
                    RequireConsent = client.RequireConsent,
                    AllowRememberConsent = client.AllowRememberConsent,
                    AllowAccessToUserInfoEndpoint = client.AllowAccessToUserInfoEndpoint,
                    AllowAccessToIntrospectionEndpoint = client.AllowAccessToIntrospectionEndpoint,
                    AllowAccessToRevocationEndpoint = client.AllowAccessToRevocationEndpoint,
                    IncludeJwtId = client.IncludeJwtId,
                    AlwaysSendClientClaims = client.AlwaysSendClientClaims,
                    AlwaysIncludeUserClaimsInIdToken = client.AlwaysIncludeUserClaimsInIdToken,
                    ClientClaimsPrefix = client.ClientClaimsPrefix,
                    RequireMfa = client.RequireMfa,
                    MfaGracePeriodMinutes = client.MfaGracePeriodMinutes,
                    AllowedMfaMethods = client.AllowedMfaMethods,
                    RememberMfaForSession = client.RememberMfaForSession,
                    RateLimitRequestsPerMinute = client.RateLimitRequestsPerMinute,
                    RateLimitRequestsPerHour = client.RateLimitRequestsPerHour,
                    RateLimitRequestsPerDay = client.RateLimitRequestsPerDay,
                    ThemeName = client.ThemeName,
                    CustomCssUrl = client.CustomCssUrl,
                    CustomJavaScriptUrl = client.CustomJavaScriptUrl,
                    PageTitlePrefix = client.PageTitlePrefix,
                    LogoUri = client.LogoUri,
                    ClientUri = client.ClientUri,
                    PolicyUri = client.PolicyUri,
                    TosUri = client.TosUri,
                    BackChannelLogoutUri = client.BackChannelLogoutUri,
                    BackChannelLogoutSessionRequired = client.BackChannelLogoutSessionRequired,
                    FrontChannelLogoutUri = client.FrontChannelLogoutUri,
                    FrontChannelLogoutSessionRequired = client.FrontChannelLogoutSessionRequired,
                    AllowedCorsOrigins = client.AllowedCorsOrigins,
                    AllowedIdentityProviders = client.AllowedIdentityProviders,
                    ProtocolType = client.ProtocolType,
                    EnableDetailedErrors = client.EnableDetailedErrors,
                    LogSensitiveData = client.LogSensitiveData,
                    EnableLocalLogin = client.EnableLocalLogin,
                    CustomLoginPageUrl = client.CustomLoginPageUrl,
                    CustomLogoutPageUrl = client.CustomLogoutPageUrl,
                    CustomErrorPageUrl = client.CustomErrorPageUrl,
                    // PAR / JAR / JARM
                    ParMode = client.ParMode,
                    JarMode = client.JarMode,
                    JarmMode = client.JarmMode,
                    RequireSignedRequestObject = client.RequireSignedRequestObject,
                    AllowedRequestObjectAlgs = client.AllowedRequestObjectAlgs
                };

                return clientDto;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error updating client '{ClientId}'", client.ClientId);
                throw;
            }
        });

        return Ok(result);
    }

    private async Task CreateOpenIddictApplication(Client client, CreateClientRequest request)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = client.ClientId,
            ClientSecret = request.ClientSecret, // use plaintext provided at creation
            DisplayName = client.Name,
            ClientType = client.ClientType == ClientType.Public 
                ? OpenIddictConstants.ClientTypes.Public 
                : OpenIddictConstants.ClientTypes.Confidential
        };

        // Add permissions based on flows
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

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        // PAR permissions and requirements
        if (client.ParMode is PushedAuthorizationMode.Enabled or PushedAuthorizationMode.Required)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
        }
        if (client.ParMode is PushedAuthorizationMode.Required)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
        }

        // Add scopes as application permissions (scp:*)
        var hasOpenId = false;
        foreach (var scope in request.Scopes)
        {
            if (string.Equals(scope, "openid", StringComparison.OrdinalIgnoreCase))
            {
                descriptor.Permissions.Add("scp:openid");
                hasOpenId = true;
            }
            else
            {
                descriptor.Permissions.Add($"scp:{scope}");
            }
        }
        if (hasOpenId)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
        }

        // Add endpoint permissions based on configured flags
        if (client.AllowAccessToUserInfoEndpoint == true && hasOpenId)
        {
            descriptor.Permissions.Add("endpoints.userinfo");
        }
        if (client.AllowAccessToRevocationEndpoint == true)
        {
            descriptor.Permissions.Add("endpoints.revocation");
        }
        if (client.AllowAccessToIntrospectionEndpoint == true)
        {
            descriptor.Permissions.Add("endpoints.introspection");
        }

        // Include any additional stored permissions verbatim (excluding legacy forms)
        foreach (var permission in request.Permissions)
        {
            if (permission is "endpoints:userinfo" or "endpoints:revocation" or "endpoints:introspection" ||
                permission is "endpoints/userinfo" or "endpoints/revocation" or "endpoints/introspection")
            {
                continue;
            }
            if (!descriptor.Permissions.Contains(permission))
            {
                descriptor.Permissions.Add(permission);
            }
        }

        // Add redirect URIs
        foreach (var uri in request.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri));
        }

        // Add post-logout redirect URIs
        foreach (var uri in request.PostLogoutUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
        }

        await _applicationManager.CreateAsync(descriptor);
    }

    private async Task UpdateOpenIddictApplication(Client client, string? plaintextSecret = null)
    {
        // Ensure we have all related navigation properties loaded for URIs/scopes/permissions
        var fullClient = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .FirstOrDefaultAsync(c => c.Id == client.Id);

        if (fullClient is null)
        {
            _logger.LogWarning("Unable to load client '{ClientId}' for OpenIddict sync.", client.ClientId);
            return;
        }

        var existing = await _applicationManager.FindByClientIdAsync(fullClient.ClientId);

        // Build a descriptor reflecting the latest state
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = fullClient.ClientId,
            DisplayName = fullClient.Name,
            ClientType = fullClient.ClientType == ClientType.Public
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential
        };

        // Determine if a secret is required for this client
        var requiresSecret = fullClient.ClientType != ClientType.Public && fullClient.RequireClientSecret;

        // If caller provided a plaintext secret (e.g., rotation), set it. Otherwise, reuse existing stored secret on update
        if (requiresSecret)
        {
            if (!string.IsNullOrWhiteSpace(plaintextSecret))
            {
                descriptor.ClientSecret = plaintextSecret;
            }
            else if (existing is OpenIddictEntityFrameworkCoreApplication efApp && !string.IsNullOrWhiteSpace(efApp.ClientSecret))
            {
                // Preserve current secret by copying the stored value from OpenIddict store (typically hashed)
                descriptor.ClientSecret = efApp.ClientSecret;
            }
        }

        // Grants/endpoints
        if (fullClient.AllowAuthorizationCodeFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }
        if (fullClient.AllowClientCredentialsFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        }
        if (fullClient.AllowPasswordFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
        }
        if (fullClient.AllowRefreshTokenFlow)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        }
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        // PAR
        if (fullClient.ParMode is PushedAuthorizationMode.Enabled or PushedAuthorizationMode.Required)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.PushedAuthorization);
        }
        if (fullClient.ParMode is PushedAuthorizationMode.Required)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
        }

        // Scopes as permissions
        var hasOpenId = false;
        foreach (var s in fullClient.Scopes.Select(s => s.Scope))
        {
            if (string.Equals(s, "openid", StringComparison.OrdinalIgnoreCase))
            {
                descriptor.Permissions.Add("scp:openid");
                hasOpenId = true;
            }
            else
            {
                descriptor.Permissions.Add($"scp:{s}");
            }
        }
        if (hasOpenId)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);
        }

        if (fullClient.AllowAccessToUserInfoEndpoint == true && hasOpenId)
        {
            descriptor.Permissions.Add("endpoints.userinfo");
        }
        if (fullClient.AllowAccessToRevocationEndpoint == true)
        {
            descriptor.Permissions.Add("endpoints.revocation");
        }
        if (fullClient.AllowAccessToIntrospectionEndpoint == true)
        {
            descriptor.Permissions.Add("endpoints.introspection");
        }

        // Additional stored permissions
        foreach (var p in fullClient.Permissions.Select(p => p.Permission))
        {
            if (p is "endpoints:userinfo" or "endpoints:revocation" or "endpoints:introspection" ||
                p is "endpoints/userinfo" or "endpoints/revocation" or "endpoints/introspection")
            {
                continue;
            }
            if (!descriptor.Permissions.Contains(p))
            {
                descriptor.Permissions.Add(p);
            }
        }

        // URIs
        foreach (var uri in fullClient.RedirectUris.Select(ru => ru.Uri))
        {
            if (Uri.TryCreate(uri, UriKind.Absolute, out var u))
            {
                descriptor.RedirectUris.Add(u);
            }
        }
        foreach (var uri in fullClient.PostLogoutUris.Select(pl => pl.Uri))
        {
            if (Uri.TryCreate(uri, UriKind.Absolute, out var u))
            {
                descriptor.PostLogoutRedirectUris.Add(u);
            }
        }

        if (existing is null)
        {
            // If missing, only create when public or when we have a plaintext/existing secret
            if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret))
            {
                _logger.LogWarning("OpenIddict application for confidential client '{ClientId}' not found and no secret provided/available. Skipping creation.", fullClient.ClientId);
                return;
            }

            await _applicationManager.CreateAsync(descriptor);
            _logger.LogInformation("OpenIddict application created for client '{ClientId}'", fullClient.ClientId);
        }
        else
        {
            // If secret is required but we still don't have one, skip update to avoid clearing it
            if (requiresSecret && string.IsNullOrWhiteSpace(descriptor.ClientSecret))
            {
                _logger.LogWarning("Skipping OpenIddict update for client '{ClientId}' because secret is required but not available. Rotate or supply plaintext to update.", fullClient.ClientId);
                return;
            }

            await _applicationManager.UpdateAsync(existing, descriptor);
            _logger.LogInformation("OpenIddict application updated for client '{ClientId}'", fullClient.ClientId);
        }
    }

    private static string GenerateClientIdFromName(string name)
    {
        var baseId = new string((name ?? "client").ToLowerInvariant()
            .Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_')
            .ToArray());
        if (string.IsNullOrWhiteSpace(baseId)) baseId = "client";
        return $"{baseId}_{Guid.NewGuid().ToString("N")[..6]}"; // short suffix to avoid collisions
    }
}