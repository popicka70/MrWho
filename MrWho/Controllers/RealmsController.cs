using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models; // ensure access to Realm, Scope, ScopeClaim
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class RealmsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<RealmsController> _logger;

    public RealmsController(ApplicationDbContext context, ILogger<RealmsController> logger)
    { _context = context; _logger = logger; }

    // ===================== LIST =====================
    /// <summary>
    /// Get all realms with pagination
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<RealmDto>>> GetRealms(int page = 1, int pageSize = 10, string? search = null)
    {
        if (page < 1) page = 1; if (pageSize < 1 || pageSize > 100) pageSize = 10;
        var query = _context.Realms.AsQueryable();
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(r => r.Name.Contains(search) || (r.Description != null && r.Description.Contains(search)));
        var totalCount = await query.CountAsync();
        var realms = await query.Skip((page - 1) * pageSize).Take(pageSize)
            .Select(r => new RealmDto
            {
                Id = r.Id,
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
                ClientCount = _context.Clients.Count(c => c.RealmId == r.Id),
                DefaultThemeName = r.DefaultThemeName,
                RealmCustomCssUrl = r.RealmCustomCssUrl,
                RealmLogoUri = r.RealmLogoUri,
                // expose JAR/JARM defaults (summary)
                DefaultJarMode = r.DefaultJarMode,
                DefaultJarmMode = r.DefaultJarmMode
            }).ToListAsync();
        return Ok(new PagedResult<RealmDto> { Items = realms, TotalCount = totalCount, Page = page, PageSize = pageSize, TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize) });
    }

    // ===================== GET =====================
    /// <summary>
    /// Get a single realm by id
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<RealmDto>> GetRealmById(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null) return NotFound();
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
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id),
            DefaultSessionTimeoutHours = realm.DefaultSessionTimeoutHours,
            DefaultRememberMeDurationDays = realm.DefaultRememberMeDurationDays,
            DefaultUseSlidingSessionExpiration = realm.DefaultUseSlidingSessionExpiration,
            DefaultCookieSameSitePolicy = realm.DefaultCookieSameSitePolicy,
            DefaultRequireHttpsForCookies = realm.DefaultRequireHttpsForCookies,
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
            DefaultJarMode = realm.DefaultJarMode,
            DefaultJarmMode = realm.DefaultJarmMode,
            DefaultRequireSignedRequestObject = realm.DefaultRequireSignedRequestObject,
            DefaultAllowedRequestObjectAlgs = realm.DefaultAllowedRequestObjectAlgs
        };
        return Ok(dto);
    }

    // ===================== EXPORT =====================
    /// <summary>
    /// Export a realm to JSON (no database IDs)
    /// </summary>
    [HttpGet("{id}/export")]
    public async Task<ActionResult<RealmExportDto>> ExportRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null) return NotFound();
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

        // Include scopes (export with claims)
        var scopes = await _context.Scopes
            .Include(s => s.Claims)
            .OrderBy(s => s.Name)
            .ToListAsync();

        foreach (var s in scopes)
        {
            // Include all for now. To exclude standard, add: if (s.IsStandard) continue;
            export.Scopes.Add(new ScopeExportDto
            {
                Name = s.Name,
                DisplayName = s.DisplayName,
                Description = s.Description,
                IsEnabled = s.IsEnabled,
                IsRequired = s.IsRequired,
                ShowInDiscoveryDocument = s.ShowInDiscoveryDocument,
                Type = s.Type,
                Claims = s.Claims.Select(c => c.ClaimType).Distinct().ToList()
            });
        }

        // Include roles (all roles for now)
        var allRoles = await _context.Roles.ToListAsync();
        var roleIds = allRoles.Select(r => r.Id).ToList();
        var roleClaims = await _context.RoleClaims
            .Where(rc => roleIds.Contains(rc.RoleId))
            .ToListAsync();

        foreach (var role in allRoles)
        {
            var claimsForRole = roleClaims.Where(rc => rc.RoleId == role.Id)
                .Select(rc => new RoleClaimDto
                {
                    Id = rc.Id.ToString(),
                    RoleId = rc.RoleId,
                    ClaimType = rc.ClaimType!,
                    ClaimValue = rc.ClaimValue!,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                }).ToList();

            export.Roles.Add(new RoleExportDto
            {
                Name = role.Name!,
                Claims = claimsForRole
            });
        }

        // Include users belonging to this realm (by realm claim)
        var users = await _context.Users.ToListAsync();
        foreach (var u in users)
        {
            // Find realm claim for user
            var uClaims = await _context.UserClaims.Where(c => c.UserId == u.Id).ToListAsync();
            var realmClaim = uClaims.FirstOrDefault(c => c.ClaimType == "realm");
            if (realmClaim?.ClaimValue != realm.Name)
                continue;

            var roleNames = await _context.UserRoles
                .Where(ur => ur.UserId == u.Id)
                .Join(_context.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name!)
                .ToListAsync();

            export.Users.Add(new UserExportDto
            {
                UserName = u.UserName!,
                Email = u.Email!,
                EmailConfirmed = u.EmailConfirmed,
                PhoneNumber = u.PhoneNumber,
                PhoneNumberConfirmed = u.PhoneNumberConfirmed,
                TwoFactorEnabled = u.TwoFactorEnabled,
                LockoutEnabled = u.LockoutEnabled,
                LockoutEnd = u.LockoutEnd,
                Claims = uClaims.Select(c => new UserClaimDto
                {
                    ClaimType = c.ClaimType!,
                    ClaimValue = c.ClaimValue!,
                    Issuer = null
                }).ToList(),
                Roles = roleNames
            });
        }

        return Ok(export);
    }

    // ===================== IMPORT =====================
    /// <summary>
    /// Import a realm from JSON (upsert by Name)
    /// </summary>
    [HttpPost("import")]
    public async Task<ActionResult<RealmDto>> ImportRealm([FromBody] RealmExportDto dto, [FromServices] UserManager<IdentityUser> userManager, [FromServices] RoleManager<IdentityRole> roleManager)
    {
        if (string.IsNullOrWhiteSpace(dto.Name)) return ValidationProblem("Realm name is required");
        var strategy = _context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            using var tx = await _context.Database.BeginTransactionAsync();
            try
            {
                var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Name == dto.Name);
                var now = DateTime.UtcNow; var userName = User?.Identity?.Name;
                if (realm == null)
                {
                    realm = new Realm { Name = dto.Name, CreatedAt = now, UpdatedAt = now, CreatedBy = userName, UpdatedBy = userName };
                    _context.Realms.Add(realm);
                }
                // update fields (including token lifetimes & defaults)
                realm.DisplayName = dto.DisplayName; realm.Description = dto.Description; realm.IsEnabled = dto.IsEnabled;
                realm.AccessTokenLifetime = dto.AccessTokenLifetime; realm.RefreshTokenLifetime = dto.RefreshTokenLifetime; realm.AuthorizationCodeLifetime = dto.AuthorizationCodeLifetime; realm.IdTokenLifetime = dto.IdTokenLifetime; realm.DeviceCodeLifetime = dto.DeviceCodeLifetime;
                realm.DefaultSessionTimeoutHours = dto.DefaultSessionTimeoutHours; realm.DefaultUseSlidingSessionExpiration = dto.DefaultUseSlidingSessionExpiration; realm.DefaultRememberMeDurationDays = dto.DefaultRememberMeDurationDays; realm.DefaultRequireHttpsForCookies = dto.DefaultRequireHttpsForCookies; realm.DefaultCookieSameSitePolicy = dto.DefaultCookieSameSitePolicy;
                realm.DefaultRequireConsent = dto.DefaultRequireConsent; realm.DefaultAllowRememberConsent = dto.DefaultAllowRememberConsent; realm.DefaultMaxRefreshTokensPerUser = dto.DefaultMaxRefreshTokensPerUser; realm.DefaultUseOneTimeRefreshTokens = dto.DefaultUseOneTimeRefreshTokens; realm.DefaultIncludeJwtId = dto.DefaultIncludeJwtId;
                realm.DefaultRequireMfa = dto.DefaultRequireMfa; realm.DefaultMfaGracePeriodMinutes = dto.DefaultMfaGracePeriodMinutes; realm.DefaultAllowedMfaMethods = dto.DefaultAllowedMfaMethods; realm.DefaultRememberMfaForSession = dto.DefaultRememberMfaForSession;
                realm.DefaultRateLimitRequestsPerMinute = dto.DefaultRateLimitRequestsPerMinute; realm.DefaultRateLimitRequestsPerHour = dto.DefaultRateLimitRequestsPerHour; realm.DefaultRateLimitRequestsPerDay = dto.DefaultRateLimitRequestsPerDay;
                realm.DefaultEnableDetailedErrors = dto.DefaultEnableDetailedErrors; realm.DefaultLogSensitiveData = dto.DefaultLogSensitiveData; realm.DefaultThemeName = dto.DefaultThemeName; realm.RealmCustomCssUrl = dto.RealmCustomCssUrl; realm.RealmLogoUri = dto.RealmLogoUri; realm.RealmUri = dto.RealmUri; realm.RealmPolicyUri = dto.RealmPolicyUri; realm.RealmTosUri = dto.RealmTosUri; realm.UpdatedAt = now; realm.UpdatedBy = userName;
                // Persist realm to ensure Id is available
                await _context.SaveChangesAsync();

                // Import scopes (upsert by Name; replace claims)
                if (dto.Scopes != null && dto.Scopes.Count > 0)
                {
                    foreach (var s in dto.Scopes)
                    {
                        if (string.IsNullOrWhiteSpace(s.Name)) continue;

                        var scope = await _context.Scopes
                            .Include(x => x.Claims)
                            .FirstOrDefaultAsync(x => x.Name == s.Name);

                        if (scope == null)
                        {
                            scope = new Scope
                            {
                                Name = s.Name,
                                CreatedAt = now,
                                CreatedBy = userName
                            };
                            _context.Scopes.Add(scope);
                        }

                        scope.DisplayName = s.DisplayName;
                        scope.Description = s.Description;
                        scope.IsEnabled = s.IsEnabled;
                        scope.IsRequired = s.IsRequired;
                        scope.ShowInDiscoveryDocument = s.ShowInDiscoveryDocument;
                        scope.Type = s.Type;
                        scope.UpdatedAt = now;
                        scope.UpdatedBy = userName;

                        // Replace claims
                        if (scope.Claims?.Count > 0)
                            _context.ScopeClaims.RemoveRange(scope.Claims);

                        foreach (var ct in (s.Claims ?? new List<string>()).Distinct())
                        {
                            _context.ScopeClaims.Add(new ScopeClaim
                            {
                                ScopeId = scope.Id,
                                ClaimType = ct
                            });
                        }
                    }

                    await _context.SaveChangesAsync();
                }

                // Import roles (upsert by Name; replace claims)
                if (dto.Roles != null && dto.Roles.Count > 0)
                {
                    foreach (var r in dto.Roles)
                    {
                        if (string.IsNullOrWhiteSpace(r.Name)) continue;

                        var role = await roleManager.FindByNameAsync(r.Name);
                        if (role == null)
                        {
                            role = new IdentityRole(r.Name);
                            var created = await roleManager.CreateAsync(role);
                            if (!created.Succeeded)
                                throw new InvalidOperationException($"Failed to create role {r.Name}: {string.Join(", ", created.Errors.Select(e => e.Description))}");
                        }

                        // Replace role claims
                        var existingClaims = await roleManager.GetClaimsAsync(role);
                        foreach (var c in existingClaims)
                        {
                            await roleManager.RemoveClaimAsync(role, c);
                        }

                        foreach (var c in r.Claims)
                        {
                            await roleManager.AddClaimAsync(role, new System.Security.Claims.Claim(c.ClaimType, c.ClaimValue));
                        }
                    }

                    await _context.SaveChangesAsync();
                }

                // Import users (upsert by UserName; set claims and roles)
                if (dto.Users != null && dto.Users.Count > 0)
                {
                    foreach (var u in dto.Users)
                    {
                        if (string.IsNullOrWhiteSpace(u.UserName)) continue;

                        var user = await userManager.FindByNameAsync(u.UserName);
                        if (user == null)
                        {
                            user = new IdentityUser
                            {
                                UserName = u.UserName,
                                Email = u.Email,
                                EmailConfirmed = u.EmailConfirmed,
                                PhoneNumber = u.PhoneNumber,
                                PhoneNumberConfirmed = u.PhoneNumberConfirmed,
                                TwoFactorEnabled = u.TwoFactorEnabled,
                                LockoutEnabled = u.LockoutEnabled,
                                LockoutEnd = u.LockoutEnd
                            };

                            var created = await userManager.CreateAsync(user, string.IsNullOrWhiteSpace(u.TempPassword) ? Guid.NewGuid().ToString("N") + "!aA1" : u.TempPassword);
                            if (!created.Succeeded)
                                throw new InvalidOperationException($"Failed to create user {u.UserName}: {string.Join(", ", created.Errors.Select(e => e.Description))}");
                        }
                        else
                        {
                            // Update mutable fields
                            user.Email = u.Email;
                            user.EmailConfirmed = u.EmailConfirmed;
                            user.PhoneNumber = u.PhoneNumber;
                            user.PhoneNumberConfirmed = u.PhoneNumberConfirmed;
                            user.TwoFactorEnabled = u.TwoFactorEnabled;
                            user.LockoutEnabled = u.LockoutEnabled;
                            user.LockoutEnd = u.LockoutEnd;
                            var update = await userManager.UpdateAsync(user);
                            if (!update.Succeeded)
                                throw new InvalidOperationException($"Failed to update user {u.UserName}: {string.Join(", ", update.Errors.Select(e => e.Description))}");
                        }

                        // Replace user claims
                        var currentClaims = await userManager.GetClaimsAsync(user);
                        foreach (var c in currentClaims)
                        {
                            await userManager.RemoveClaimAsync(user, c);
                        }

                        foreach (var c in u.Claims)
                        {
                            await userManager.AddClaimAsync(user, new System.Security.Claims.Claim(c.ClaimType, c.ClaimValue));
                        }

                        // Ensure realm claim matches imported realm
                        if (!u.Claims.Any(c => c.ClaimType == "realm" && c.ClaimValue == dto.Name))
                        {
                            await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("realm", dto.Name));
                        }

                        // Replace roles
                        var currentRoles = await userManager.GetRolesAsync(user);
                        if (currentRoles.Count > 0)
                        {
                            var remove = await userManager.RemoveFromRolesAsync(user, currentRoles);
                            if (!remove.Succeeded)
                                throw new InvalidOperationException($"Failed to clear roles for user {u.UserName}: {string.Join(", ", remove.Errors.Select(e => e.Description))}");
                        }

                        foreach (var rn in u.Roles.Distinct())
                        {
                            if (!string.IsNullOrWhiteSpace(rn))
                            {
                                // Ensure role exists
                                var role = await roleManager.FindByNameAsync(rn);
                                if (role == null)
                                {
                                    role = new IdentityRole(rn);
                                    var created = await roleManager.CreateAsync(role);
                                    if (!created.Succeeded)
                                        throw new InvalidOperationException($"Failed to create role {rn}: {string.Join(", ", created.Errors.Select(e => e.Description))}");
                                }

                                var added = await userManager.AddToRoleAsync(user, rn);
                                if (!added.Succeeded)
                                    throw new InvalidOperationException($"Failed to add role {rn} to user {u.UserName}: {string.Join(", ", added.Errors.Select(e => e.Description))}");
                            }
                        }
                    }

                    await _context.SaveChangesAsync();
                }

                // Import clients (existing code)
                // ...existing clients import...

                await tx.CommitAsync();

                return Ok(new RealmDto
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
                });
            }
            catch (Exception ex)
            {
                await tx.RollbackAsync();
                _logger.LogError(ex, "Failed to import realm {RealmName}", dto.Name);
                return Problem(title: "Failed to import realm", detail: ex.Message);
            }
        });
    }

    // ===================== CREATE =====================
    /// <summary>
    /// Create a new realm
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<RealmDto>> CreateRealm([FromBody] CreateRealmRequest request)
    {
        if (!ModelState.IsValid) return ValidationProblem(ModelState);
        if (await _context.Realms.AnyAsync(r => r.Name == request.Name)) { ModelState.AddModelError(nameof(request.Name), "A realm with this name already exists."); return ValidationProblem(ModelState); }
        var now = DateTime.UtcNow; var userName = User?.Identity?.Name;
        var realm = new Realm { Name = request.Name, DisplayName = request.DisplayName, Description = request.Description, IsEnabled = request.IsEnabled, AccessTokenLifetime = request.AccessTokenLifetime, RefreshTokenLifetime = request.RefreshTokenLifetime, AuthorizationCodeLifetime = request.AuthorizationCodeLifetime, CreatedAt = now, UpdatedAt = now, CreatedBy = userName, UpdatedBy = userName };
        _context.Realms.Add(realm); await _context.SaveChangesAsync();
        return CreatedAtAction(nameof(GetRealmById), new { id = realm.Id }, new RealmDto { Id = realm.Id, Name = realm.Name, Description = realm.Description, DisplayName = realm.DisplayName, IsEnabled = realm.IsEnabled, AccessTokenLifetime = realm.AccessTokenLifetime, RefreshTokenLifetime = realm.RefreshTokenLifetime, AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime, IdTokenLifetime = realm.IdTokenLifetime, DeviceCodeLifetime = realm.DeviceCodeLifetime, CreatedAt = realm.CreatedAt, UpdatedAt = realm.UpdatedAt, CreatedBy = realm.CreatedBy, UpdatedBy = realm.UpdatedBy, ClientCount = 0 });
    }

    // ===================== UPDATE BASIC =====================
    /// <summary>
    /// Update an existing realm
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<RealmDto>> UpdateRealm(string id, [FromBody] CreateRealmRequest request)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id); if (realm == null) return NotFound();
        realm.DisplayName = request.DisplayName; realm.Description = request.Description; realm.IsEnabled = request.IsEnabled; realm.AccessTokenLifetime = request.AccessTokenLifetime; realm.RefreshTokenLifetime = request.RefreshTokenLifetime; realm.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime; realm.UpdatedAt = DateTime.UtcNow; realm.UpdatedBy = User?.Identity?.Name; await _context.SaveChangesAsync();
        return Ok(new RealmDto { Id = realm.Id, Name = realm.Name, Description = realm.Description, DisplayName = realm.DisplayName, IsEnabled = realm.IsEnabled, AccessTokenLifetime = realm.AccessTokenLifetime, RefreshTokenLifetime = realm.RefreshTokenLifetime, AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime, IdTokenLifetime = realm.IdTokenLifetime, DeviceCodeLifetime = realm.DeviceCodeLifetime, CreatedAt = realm.CreatedAt, UpdatedAt = realm.UpdatedAt, CreatedBy = realm.CreatedBy, UpdatedBy = realm.UpdatedBy, ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id) });
    }

    // ===================== DELETE =====================
    /// <summary>
    /// Delete a realm
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id); if (realm == null) return NotFound();
        if (await _context.Clients.AnyAsync(c => c.RealmId == realm.Id)) return Conflict(new { message = "Cannot delete a realm that has clients." });
        _context.Realms.Remove(realm); await _context.SaveChangesAsync(); return NoContent();
    }

    // ===================== TOGGLE =====================
    /// <summary>
    /// Toggle realm enabled/disabled
    /// </summary>
    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<RealmDto>> ToggleRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id); if (realm == null) return NotFound();
        realm.IsEnabled = !realm.IsEnabled; realm.UpdatedAt = DateTime.UtcNow; realm.UpdatedBy = User?.Identity?.Name; await _context.SaveChangesAsync();
        return Ok(new RealmDto { Id = realm.Id, Name = realm.Name, Description = realm.Description, DisplayName = realm.DisplayName, IsEnabled = realm.IsEnabled, AccessTokenLifetime = realm.AccessTokenLifetime, RefreshTokenLifetime = realm.RefreshTokenLifetime, AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime, IdTokenLifetime = realm.IdTokenLifetime, DeviceCodeLifetime = realm.DeviceCodeLifetime, CreatedAt = realm.CreatedAt, UpdatedAt = realm.UpdatedAt, CreatedBy = realm.CreatedBy, UpdatedBy = realm.UpdatedBy, ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id) });
    }

    // ===================== UPDATE DEFAULTS =====================
    /// <summary>
    /// Update default configuration and branding for a realm
    /// </summary>
    [HttpPut("{id}/defaults")]
    public async Task<ActionResult<RealmDto>> UpdateDefaults(string id, [FromBody] UpdateRealmDefaultsRequest request)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id); if (realm == null) return NotFound();
        realm.AccessTokenLifetime = request.AccessTokenLifetime; realm.RefreshTokenLifetime = request.RefreshTokenLifetime; realm.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime; realm.IdTokenLifetime = request.IdTokenLifetime; realm.DeviceCodeLifetime = request.DeviceCodeLifetime;
        realm.DefaultSessionTimeoutHours = request.DefaultSessionTimeoutHours; realm.DefaultRememberMeDurationDays = request.DefaultRememberMeDurationDays; realm.DefaultUseSlidingSessionExpiration = request.DefaultUseSlidingSessionExpiration; realm.DefaultCookieSameSitePolicy = request.DefaultCookieSameSitePolicy; realm.DefaultRequireHttpsForCookies = request.DefaultRequireHttpsForCookies;
        realm.DefaultRequireConsent = request.DefaultRequireConsent; realm.DefaultAllowRememberConsent = request.DefaultAllowRememberConsent; realm.DefaultMaxRefreshTokensPerUser = request.DefaultMaxRefreshTokensPerUser; realm.DefaultUseOneTimeRefreshTokens = request.DefaultUseOneTimeRefreshTokens; realm.DefaultIncludeJwtId = request.DefaultIncludeJwtId;
        realm.DefaultRequireMfa = request.DefaultRequireMfa; realm.DefaultMfaGracePeriodMinutes = request.DefaultMfaGracePeriodMinutes; realm.DefaultAllowedMfaMethods = request.DefaultAllowedMfaMethods; realm.DefaultRememberMfaForSession = request.DefaultRememberMfaForSession;
        realm.DefaultRateLimitRequestsPerMinute = request.DefaultRateLimitRequestsPerMinute; realm.DefaultRateLimitRequestsPerHour = request.DefaultRateLimitRequestsPerHour; realm.DefaultRateLimitRequestsPerDay = request.DefaultRateLimitRequestsPerDay; realm.DefaultEnableDetailedErrors = request.DefaultEnableDetailedErrors; realm.DefaultLogSensitiveData = request.DefaultLogSensitiveData; realm.DefaultThemeName = request.DefaultThemeName; realm.RealmCustomCssUrl = request.RealmCustomCssUrl; realm.RealmLogoUri = request.RealmLogoUri; realm.RealmUri = request.RealmUri; realm.RealmPolicyUri = request.RealmPolicyUri; realm.RealmTosUri = request.RealmTosUri;
        realm.DefaultJarMode = request.DefaultJarMode; realm.DefaultJarmMode = request.DefaultJarmMode; realm.DefaultRequireSignedRequestObject = request.DefaultRequireSignedRequestObject; realm.DefaultAllowedRequestObjectAlgs = request.DefaultAllowedRequestObjectAlgs;
        realm.UpdatedAt = DateTime.UtcNow; realm.UpdatedBy = User?.Identity?.Name; await _context.SaveChangesAsync();
        return await GetRealmById(id);
    }
}