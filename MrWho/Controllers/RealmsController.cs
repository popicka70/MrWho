using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Shared;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class RealmsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<RealmsController> _logger;

    public RealmsController(ApplicationDbContext context, ILogger<RealmsController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get all realms with pagination
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<RealmDto>>> GetRealms(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var query = _context.Realms.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(r => r.Name.Contains(search) || 
                                   (r.Description != null && r.Description.Contains(search)));
        }

        var totalCount = await query.CountAsync();
        var realms = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new RealmDto
            {
                Id = r.Id.ToString(),
                Name = r.Name,
                Description = r.Description,
                DisplayName = r.DisplayName,
                IsEnabled = r.IsEnabled,
                AccessTokenLifetime = r.AccessTokenLifetime,
                RefreshTokenLifetime = r.RefreshTokenLifetime,
                AuthorizationCodeLifetime = r.AuthorizationCodeLifetime,
                CreatedAt = r.CreatedAt,
                UpdatedAt = r.UpdatedAt,
                CreatedBy = r.CreatedBy,
                UpdatedBy = r.UpdatedBy,
                ClientCount = _context.Clients.Count(c => c.RealmId == r.Id)
            })
            .ToListAsync();

        var result = new PagedResult<RealmDto>
        {
            Items = realms,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        return Ok(result);
    }

    /// <summary>
    /// Get a single realm by id
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<RealmDto>> GetRealmById(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(dto);
    }

    /// <summary>
    /// Export a realm to JSON (no database IDs)
    /// </summary>
    [HttpGet("{id}/export")]
    public async Task<ActionResult<RealmExportDto>> ExportRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        var export = new RealmExportDto
        {
            Name = realm.Name,
            DisplayName = realm.DisplayName,
            Description = realm.Description,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            DefaultSessionTimeoutHours = realm.DefaultSessionTimeoutHours,
            DefaultUseSlidingSessionExpiration = realm.DefaultUseSlidingSessionExpiration,
            DefaultRememberMeDurationDays = realm.DefaultRememberMeDurationDays,
            DefaultRequireHttpsForCookies = realm.DefaultRequireHttpsForCookies,
            DefaultCookieSameSitePolicy = realm.DefaultCookieSameSitePolicy,
            DefaultRequireConsent = realm.DefaultRequireConsent,
            DefaultAllowRememberConsent = realm.DefaultAllowRememberConsent,
            DefaultMaxRefreshTokensPerUser = realm.DefaultMaxRefreshTokensPerUser,
            DefaultUseOneTimeRefreshTokens = realm.DefaultUseOneTimeRefreshTokens,
            DefaultIncludeJwtId = realm.DefaultIncludeJwtId,
            DefaultRequireMfa = realm.DefaultRequireMfa,
            DefaultMfaGracePeriodMinutes = realm.DefaultMfaGracePeriodMinutes,
            DefaultAllowedMfaMethods = realm.DefaultAllowedMfaMethods,
            DefaultRememberMfaForSession = realm.DefaultRememberMfaForSession,
            DefaultRateLimitRequestsPerMinute = realm.DefaultRateLimitRequestsPerMinute,
            DefaultRateLimitRequestsPerHour = realm.DefaultRateLimitRequestsPerHour,
            DefaultRateLimitRequestsPerDay = realm.DefaultRateLimitRequestsPerDay,
            DefaultEnableDetailedErrors = realm.DefaultEnableDetailedErrors,
            DefaultLogSensitiveData = realm.DefaultLogSensitiveData,
            DefaultThemeName = realm.DefaultThemeName,
            RealmCustomCssUrl = realm.RealmCustomCssUrl,
            RealmLogoUri = realm.RealmLogoUri,
            RealmUri = realm.RealmUri,
            RealmPolicyUri = realm.RealmPolicyUri,
            RealmTosUri = realm.RealmTosUri,
            ExportedBy = User?.Identity?.Name ?? "System",
            ExportedAtUtc = DateTime.UtcNow,
            FormatVersion = "1.0"
        };

        // Include clients belonging to this realm
        var clients = await _context.Clients
            .Include(c => c.RedirectUris)
            .Include(c => c.PostLogoutUris)
            .Include(c => c.Scopes)
            .Include(c => c.Permissions)
            .Where(c => c.RealmId == realm.Id)
            .ToListAsync();

        foreach (var c in clients)
        {
            export.Clients.Add(new ClientExportDto
            {
                ClientId = c.ClientId,
                Name = c.Name,
                Description = c.Description,
                IsEnabled = c.IsEnabled,
                ClientType = c.ClientType,
                RealmName = realm.Name,
                AllowAuthorizationCodeFlow = c.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = c.AllowClientCredentialsFlow,
                AllowPasswordFlow = c.AllowPasswordFlow,
                AllowRefreshTokenFlow = c.AllowRefreshTokenFlow,
                RequirePkce = c.RequirePkce,
                RequireClientSecret = c.RequireClientSecret,
                AccessTokenLifetime = c.AccessTokenLifetime,
                RefreshTokenLifetime = c.RefreshTokenLifetime,
                AuthorizationCodeLifetime = c.AuthorizationCodeLifetime,
                IdTokenLifetimeMinutes = c.IdTokenLifetimeMinutes,
                DeviceCodeLifetimeMinutes = c.DeviceCodeLifetimeMinutes,
                SessionTimeoutHours = c.SessionTimeoutHours,
                UseSlidingSessionExpiration = c.UseSlidingSessionExpiration,
                RememberMeDurationDays = c.RememberMeDurationDays,
                RequireHttpsForCookies = c.RequireHttpsForCookies,
                CookieSameSitePolicy = c.CookieSameSitePolicy,
                RequireConsent = c.RequireConsent,
                AllowRememberConsent = c.AllowRememberConsent,
                IncludeJwtId = c.IncludeJwtId,
                AlwaysSendClientClaims = c.AlwaysSendClientClaims,
                AlwaysIncludeUserClaimsInIdToken = c.AlwaysIncludeUserClaimsInIdToken,
                ClientClaimsPrefix = c.ClientClaimsPrefix,
                AllowAccessToUserInfoEndpoint = c.AllowAccessToUserInfoEndpoint,
                AllowAccessToIntrospectionEndpoint = c.AllowAccessToIntrospectionEndpoint,
                AllowAccessToRevocationEndpoint = c.AllowAccessToRevocationEndpoint,
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
                RedirectUris = c.RedirectUris.Select(x => x.Uri).ToList(),
                PostLogoutUris = c.PostLogoutUris.Select(x => x.Uri).ToList(),
                Scopes = c.Scopes.Select(x => x.Scope).ToList(),
                Permissions = c.Permissions.Select(x => x.Permission).ToList(),
                ExportedBy = User?.Identity?.Name ?? "System",
                ExportedAtUtc = DateTime.UtcNow,
                FormatVersion = "1.0"
            });
        }

        return Ok(export);
    }

    /// <summary>
    /// Import a realm from JSON (upsert by Name)
    /// </summary>
    [HttpPost("import")]
    public async Task<ActionResult<RealmDto>> ImportRealm([FromBody] RealmExportDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Name))
        {
            return ValidationProblem("Realm name is required");
        }

        var strategy = _context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            using var tx = await _context.Database.BeginTransactionAsync();
            try
            {
                var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == dto.Name);
                var now = DateTime.UtcNow;
                var userName = User?.Identity?.Name;

                if (realm == null)
                {
                    realm = new Realm
                    {
                        Name = dto.Name,
                        CreatedAt = now,
                        UpdatedAt = now,
                        CreatedBy = userName,
                        UpdatedBy = userName
                    };
                    _context.Realms.Add(realm);
                }

                // Update fields
                realm.DisplayName = dto.DisplayName;
                realm.Description = dto.Description;
                realm.IsEnabled = dto.IsEnabled;
                realm.AccessTokenLifetime = dto.AccessTokenLifetime;
                realm.RefreshTokenLifetime = dto.RefreshTokenLifetime;
                realm.AuthorizationCodeLifetime = dto.AuthorizationCodeLifetime;
                realm.IdTokenLifetime = dto.IdTokenLifetime;
                realm.DeviceCodeLifetime = dto.DeviceCodeLifetime;
                realm.DefaultSessionTimeoutHours = dto.DefaultSessionTimeoutHours;
                realm.DefaultUseSlidingSessionExpiration = dto.DefaultUseSlidingSessionExpiration;
                realm.DefaultRememberMeDurationDays = dto.DefaultRememberMeDurationDays;
                realm.DefaultRequireHttpsForCookies = dto.DefaultRequireHttpsForCookies;
                realm.DefaultCookieSameSitePolicy = dto.DefaultCookieSameSitePolicy;
                realm.DefaultRequireConsent = dto.DefaultRequireConsent;
                realm.DefaultAllowRememberConsent = dto.DefaultAllowRememberConsent;
                realm.DefaultMaxRefreshTokensPerUser = dto.DefaultMaxRefreshTokensPerUser;
                realm.DefaultUseOneTimeRefreshTokens = dto.DefaultUseOneTimeRefreshTokens;
                realm.DefaultIncludeJwtId = dto.DefaultIncludeJwtId;
                realm.DefaultRequireMfa = dto.DefaultRequireMfa;
                realm.DefaultMfaGracePeriodMinutes = dto.DefaultMfaGracePeriodMinutes;
                realm.DefaultAllowedMfaMethods = dto.DefaultAllowedMfaMethods;
                realm.DefaultRememberMfaForSession = dto.DefaultRememberMfaForSession;
                realm.DefaultRateLimitRequestsPerMinute = dto.DefaultRateLimitRequestsPerMinute;
                realm.DefaultRateLimitRequestsPerHour = dto.DefaultRateLimitRequestsPerHour;
                realm.DefaultRateLimitRequestsPerDay = dto.DefaultRateLimitRequestsPerDay;
                realm.DefaultEnableDetailedErrors = dto.DefaultEnableDetailedErrors;
                realm.DefaultLogSensitiveData = dto.DefaultLogSensitiveData;
                realm.DefaultThemeName = dto.DefaultThemeName;
                realm.RealmCustomCssUrl = dto.RealmCustomCssUrl;
                realm.RealmLogoUri = dto.RealmLogoUri;
                realm.RealmUri = dto.RealmUri;
                realm.RealmPolicyUri = dto.RealmPolicyUri;
                realm.RealmTosUri = dto.RealmTosUri;
                realm.UpdatedAt = now;
                realm.UpdatedBy = userName;

                // Persist realm to ensure Id is available
                await _context.SaveChangesAsync();

                // Optionally import included clients
                if (dto.Clients != null && dto.Clients.Count > 0)
                {
                    foreach (var c in dto.Clients)
                    {
                        if (string.IsNullOrWhiteSpace(c.ClientId))
                            continue;

                        // Upsert client within this realm
                        var client = await _context.Clients
                            .Include(x => x.RedirectUris)
                            .Include(x => x.PostLogoutUris)
                            .Include(x => x.Scopes)
                            .Include(x => x.Permissions)
                            .FirstOrDefaultAsync(x => x.ClientId == c.ClientId && x.RealmId == realm.Id);

                        string? generatedSecret = null;

                        if (client == null)
                        {
                            client = new Client
                            {
                                ClientId = c.ClientId,
                                RealmId = realm.Id,
                                CreatedAt = now,
                                UpdatedAt = now,
                                CreatedBy = userName,
                                UpdatedBy = userName
                            };
                            _context.Clients.Add(client);

                            // If confidential/machine and requires secret, generate one
                            if ((c.ClientType == ClientType.Confidential || c.ClientType == ClientType.Machine) && c.RequireClientSecret == true)
                            {
                                generatedSecret = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
                                client.ClientSecret = generatedSecret;
                            }
                        }

                        // Update scalar properties
                        client.Name = c.Name;
                        client.Description = c.Description;
                        client.IsEnabled = c.IsEnabled;
                        client.ClientType = c.ClientType;
                        client.AllowAuthorizationCodeFlow = c.AllowAuthorizationCodeFlow;
                        client.AllowClientCredentialsFlow = c.AllowClientCredentialsFlow;
                        client.AllowPasswordFlow = c.AllowPasswordFlow;
                        client.AllowRefreshTokenFlow = c.AllowRefreshTokenFlow;
                        client.RequirePkce = c.RequirePkce;
                        client.RequireClientSecret = c.RequireClientSecret;
                        client.AccessTokenLifetime = c.AccessTokenLifetime;
                        client.RefreshTokenLifetime = c.RefreshTokenLifetime;
                        client.AuthorizationCodeLifetime = c.AuthorizationCodeLifetime;
                        client.IdTokenLifetimeMinutes = c.IdTokenLifetimeMinutes;
                        client.DeviceCodeLifetimeMinutes = c.DeviceCodeLifetimeMinutes;
                        client.SessionTimeoutHours = c.SessionTimeoutHours;
                        client.UseSlidingSessionExpiration = c.UseSlidingSessionExpiration;
                        client.RememberMeDurationDays = c.RememberMeDurationDays;
                        client.RequireHttpsForCookies = c.RequireHttpsForCookies;
                        client.CookieSameSitePolicy = c.CookieSameSitePolicy;
                        client.RequireConsent = c.RequireConsent;
                        client.AllowRememberConsent = c.AllowRememberConsent;
                        client.IncludeJwtId = c.IncludeJwtId;
                        client.AlwaysSendClientClaims = c.AlwaysSendClientClaims;
                        client.AlwaysIncludeUserClaimsInIdToken = c.AlwaysIncludeUserClaimsInIdToken;
                        client.ClientClaimsPrefix = c.ClientClaimsPrefix;
                        client.AllowAccessToUserInfoEndpoint = c.AllowAccessToUserInfoEndpoint;
                        client.AllowAccessToIntrospectionEndpoint = c.AllowAccessToIntrospectionEndpoint;
                        client.AllowAccessToRevocationEndpoint = c.AllowAccessToRevocationEndpoint;
                        client.RateLimitRequestsPerMinute = c.RateLimitRequestsPerMinute;
                        client.RateLimitRequestsPerHour = c.RateLimitRequestsPerHour;
                        client.RateLimitRequestsPerDay = c.RateLimitRequestsPerDay;
                        client.ThemeName = c.ThemeName;
                        client.CustomCssUrl = c.CustomCssUrl;
                        client.CustomJavaScriptUrl = c.CustomJavaScriptUrl;
                        client.PageTitlePrefix = c.PageTitlePrefix;
                        client.LogoUri = c.LogoUri;
                        client.ClientUri = c.ClientUri;
                        client.PolicyUri = c.PolicyUri;
                        client.TosUri = c.TosUri;
                        client.BackChannelLogoutUri = c.BackChannelLogoutUri;
                        client.BackChannelLogoutSessionRequired = c.BackChannelLogoutSessionRequired;
                        client.FrontChannelLogoutUri = c.FrontChannelLogoutUri;
                        client.FrontChannelLogoutSessionRequired = c.FrontChannelLogoutSessionRequired;
                        client.AllowedCorsOrigins = c.AllowedCorsOrigins;
                        client.AllowedIdentityProviders = c.AllowedIdentityProviders;
                        client.ProtocolType = c.ProtocolType;
                        client.EnableDetailedErrors = c.EnableDetailedErrors;
                        client.LogSensitiveData = c.LogSensitiveData;
                        client.EnableLocalLogin = c.EnableLocalLogin;
                        client.CustomLoginPageUrl = c.CustomLoginPageUrl;
                        client.CustomLogoutPageUrl = c.CustomLogoutPageUrl;
                        client.CustomErrorPageUrl = c.CustomErrorPageUrl;
                        client.UpdatedAt = now;
                        client.UpdatedBy = userName;

                        // Collections - replace
                        if (client.RedirectUris?.Count > 0)
                            _context.ClientRedirectUris.RemoveRange(client.RedirectUris);
                        foreach (var uri in (c.RedirectUris ?? new List<string>()).Distinct())
                        {
                            _context.ClientRedirectUris.Add(new ClientRedirectUri { ClientId = client.Id, Uri = uri });
                        }

                        if (client.PostLogoutUris?.Count > 0)
                            _context.ClientPostLogoutUris.RemoveRange(client.PostLogoutUris);
                        foreach (var uri in (c.PostLogoutUris ?? new List<string>()).Distinct())
                        {
                            _context.ClientPostLogoutUris.Add(new ClientPostLogoutUri { ClientId = client.Id, Uri = uri });
                        }

                        if (client.Scopes?.Count > 0)
                            _context.ClientScopes.RemoveRange(client.Scopes);
                        foreach (var s in (c.Scopes ?? new List<string>()).Distinct())
                        {
                            _context.ClientScopes.Add(new ClientScope { ClientId = client.Id, Scope = s });
                        }

                        if (client.Permissions?.Count > 0)
                            _context.ClientPermissions.RemoveRange(client.Permissions);
                        foreach (var p in (c.Permissions ?? new List<string>()).Distinct())
                        {
                            _context.ClientPermissions.Add(new ClientPermission { ClientId = client.Id, Permission = p });
                        }
                    }

                    await _context.SaveChangesAsync();
                }

                await tx.CommitAsync();

                var result = new RealmDto
                {
                    Id = realm.Id,
                    Name = realm.Name,
                    Description = realm.Description,
                    DisplayName = realm.DisplayName,
                    IsEnabled = realm.IsEnabled,
                    AccessTokenLifetime = realm.AccessTokenLifetime,
                    RefreshTokenLifetime = realm.RefreshTokenLifetime,
                    AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
                    IdTokenLifetime = realm.IdTokenLifetime,
                    DeviceCodeLifetime = realm.DeviceCodeLifetime,
                    CreatedAt = realm.CreatedAt,
                    UpdatedAt = realm.UpdatedAt,
                    CreatedBy = realm.CreatedBy,
                    UpdatedBy = realm.UpdatedBy,
                    ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
                };

                return Ok(result);
            }
            catch (Exception ex)
            {
                await tx.RollbackAsync();
                _logger.LogError(ex, "Failed to import realm {RealmName}", dto.Name);
                return Problem(title: "Failed to import realm", detail: ex.Message);
            }
        });
    }

    /// <summary>
    /// Create a new realm
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<RealmDto>> CreateRealm([FromBody] CreateRealmRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        // Ensure unique name
        var exists = await _context.Realms.AnyAsync(r => r.Name == request.Name);
        if (exists)
        {
            ModelState.AddModelError(nameof(request.Name), "A realm with this name already exists.");
            return ValidationProblem(ModelState);
        }

        var now = DateTime.UtcNow;
        var userName = User?.Identity?.Name;

        var realm = new Realm
        {
            Name = request.Name,
            DisplayName = request.DisplayName,
            Description = request.Description,
            IsEnabled = request.IsEnabled,
            AccessTokenLifetime = request.AccessTokenLifetime,
            RefreshTokenLifetime = request.RefreshTokenLifetime,
            AuthorizationCodeLifetime = request.AuthorizationCodeLifetime,
            // Keep IdTokenLifetime and DeviceCodeLifetime defaults from model
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = userName,
            UpdatedBy = userName
        };

        _context.Realms.Add(realm);
        await _context.SaveChangesAsync();

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = 0
        };

        return CreatedAtAction(nameof(GetRealmById), new { id = realm.Id }, dto);
    }

    /// <summary>
    /// Update an existing realm
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<RealmDto>> UpdateRealm(string id, [FromBody] CreateRealmRequest request)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        // Name is considered immutable by UI, but if provided different, keep original
        realm.DisplayName = request.DisplayName;
        realm.Description = request.Description;
        realm.IsEnabled = request.IsEnabled;
        realm.AccessTokenLifetime = request.AccessTokenLifetime;
        realm.RefreshTokenLifetime = request.RefreshTokenLifetime;
        realm.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime;
        realm.UpdatedAt = DateTime.UtcNow;
        realm.UpdatedBy = User?.Identity?.Name;

        await _context.SaveChangesAsync();

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(dto);
    }

    /// <summary>
    /// Delete a realm
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        // Optionally, prevent deletion if clients exist
        var clientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id);
        if (clientCount > 0)
        {
            return Conflict(new { message = "Cannot delete a realm that has clients." });
        }

        _context.Realms.Remove(realm);
        await _context.SaveChangesAsync();
        return NoContent();
    }

    /// <summary>
    /// Toggle realm enabled/disabled
    /// </summary>
    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<RealmDto>> ToggleRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        realm.IsEnabled = !realm.IsEnabled;
        realm.UpdatedAt = DateTime.UtcNow;
        realm.UpdatedBy = User?.Identity?.Name;
        await _context.SaveChangesAsync();

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(dto);
    }
}