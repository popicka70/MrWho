using System.ComponentModel.DataAnnotations;
using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// Request to update a client
/// </summary>
public class UpdateClientRequest
{
    [StringLength(500)]
    public string? ClientSecret { get; set; }

    [StringLength(200)]
    public string? Name { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    public bool? IsEnabled { get; set; }
    public ClientType? ClientType { get; set; }
    public bool? AllowAuthorizationCodeFlow { get; set; }
    public bool? AllowClientCredentialsFlow { get; set; }
    public bool? AllowPasswordFlow { get; set; }
    public bool? AllowRefreshTokenFlow { get; set; }
    public bool? AllowDeviceCodeFlow { get; set; } // NEW
    public bool? RequirePkce { get; set; }
    public bool? RequireClientSecret { get; set; }

    // PAR mode
    public PushedAuthorizationMode? ParMode { get; set; }
    public JarMode? JarMode { get; set; }
    public JarmMode? JarmMode { get; set; }
    public bool? RequireSignedRequestObject { get; set; }
    public string? AllowedRequestObjectAlgs { get; set; }
    public string? JarRsaPublicKeyPem { get; set; } // NEW

    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }
    public List<string>? RedirectUris { get; set; }
    public List<string>? PostLogoutUris { get; set; }
    public List<string>? Scopes { get; set; }
    public List<string>? Permissions { get; set; }
    public List<string>? Audiences { get; set; }

    // === DYNAMIC CONFIGURATION PARAMETERS ===

    // Session & Cookie Configuration
    public int? SessionTimeoutHours { get; set; }
    public bool? UseSlidingSessionExpiration { get; set; }
    public int? RememberMeDurationDays { get; set; }
    public bool? RequireHttpsForCookies { get; set; }

    [StringLength(20)]
    public string? CookieSameSitePolicy { get; set; }

    // Token Lifecycle Configuration
    public int? IdTokenLifetimeMinutes { get; set; }
    public int? DeviceCodeLifetimeMinutes { get; set; }

    [StringLength(20)]
    public string? AccessTokenType { get; set; }

    public bool? UseOneTimeRefreshTokens { get; set; }
    public int? MaxRefreshTokensPerUser { get; set; }
    public bool? HashAccessTokens { get; set; }
    public bool? UpdateAccessTokenClaimsOnRefresh { get; set; }

    // Security & Compliance Configuration
    public bool? RequireConsent { get; set; }
    public bool? AllowRememberConsent { get; set; }
    public bool? AllowAccessToUserInfoEndpoint { get; set; }
    public bool? AllowAccessToIntrospectionEndpoint { get; set; }
    public bool? AllowAccessToRevocationEndpoint { get; set; }
    public bool? IncludeJwtId { get; set; }
    public bool? AlwaysSendClientClaims { get; set; }
    public bool? AlwaysIncludeUserClaimsInIdToken { get; set; }

    [StringLength(100)]
    public string? ClientClaimsPrefix { get; set; }

    // Multi-Factor Authentication Configuration
    public bool? RequireMfa { get; set; }
    public int? MfaGracePeriodMinutes { get; set; }

    [StringLength(1000)]
    public string? AllowedMfaMethods { get; set; }

    public bool? RememberMfaForSession { get; set; }

    // Rate Limiting Configuration
    public int? RateLimitRequestsPerMinute { get; set; }
    public int? RateLimitRequestsPerHour { get; set; }
    public int? RateLimitRequestsPerDay { get; set; }

    // Branding & Customization Configuration
    [StringLength(100)]
    public string? ThemeName { get; set; }

    [StringLength(2000)]
    public string? CustomCssUrl { get; set; }

    [StringLength(2000)]
    public string? CustomJavaScriptUrl { get; set; }

    [StringLength(200)]
    public string? PageTitlePrefix { get; set; }

    [StringLength(2000)]
    public string? LogoUri { get; set; }

    [StringLength(2000)]
    public string? ClientUri { get; set; }

    [StringLength(2000)]
    public string? PolicyUri { get; set; }

    [StringLength(2000)]
    public string? TosUri { get; set; }

    // Logout & Integration Configuration
    [StringLength(2000)]
    public string? BackChannelLogoutUri { get; set; }

    public bool? BackChannelLogoutSessionRequired { get; set; }

    [StringLength(2000)]
    public string? FrontChannelLogoutUri { get; set; }

    public bool? FrontChannelLogoutSessionRequired { get; set; }

    [StringLength(4000)]
    public string? AllowedCorsOrigins { get; set; }

    [StringLength(2000)]
    public string? AllowedIdentityProviders { get; set; }

    // Advanced Configuration
    [StringLength(50)]
    public string? ProtocolType { get; set; }

    public bool? EnableDetailedErrors { get; set; }
    public bool? LogSensitiveData { get; set; }
    public bool? EnableLocalLogin { get; set; }

    [StringLength(2000)]
    public string? CustomLoginPageUrl { get; set; }

    [StringLength(2000)]
    public string? CustomLogoutPageUrl { get; set; }

    [StringLength(2000)]
    public string? CustomErrorPageUrl { get; set; }

    // Login options (new)
    public bool? AllowPasskeyLogin { get; set; }
    public bool? AllowQrLoginQuick { get; set; }
    public bool? AllowQrLoginSecure { get; set; }
    public bool? AllowCodeLogin { get; set; }

    // Audience Configuration
    public AudienceMode? AudienceMode { get; set; }
    [StringLength(200)]
    public string? PrimaryAudience { get; set; }
    public bool? IncludeAudInIdToken { get; set; }
    public bool? RequireExplicitAudienceScope { get; set; }

    // Role inclusion override
    public ClientRoleInclusionOverride? RoleInclusionOverride { get; set; }
}