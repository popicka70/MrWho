using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// DTO for client data
/// </summary>
public class ClientDto
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; }
    public ClientType ClientType { get; set; }
    public bool AllowAuthorizationCodeFlow { get; set; }
    public bool AllowClientCredentialsFlow { get; set; }
    public bool AllowPasswordFlow { get; set; }
    public bool AllowRefreshTokenFlow { get; set; }
    public bool RequirePkce { get; set; }
    public bool RequireClientSecret { get; set; }
    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }
    public string RealmId { get; set; } = string.Empty;
    public string RealmName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutUris { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
    public List<string> Audiences { get; set; } = new();

    // === DYNAMIC CONFIGURATION PARAMETERS ===

    // Session & Cookie Configuration
    public int? SessionTimeoutHours { get; set; }
    public bool? UseSlidingSessionExpiration { get; set; }
    public int? RememberMeDurationDays { get; set; }
    public bool? RequireHttpsForCookies { get; set; }
    public string? CookieSameSitePolicy { get; set; }

    // Token Lifecycle Configuration
    public int? IdTokenLifetimeMinutes { get; set; }
    public int? DeviceCodeLifetimeMinutes { get; set; }
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
    public string? ClientClaimsPrefix { get; set; }

    // Multi-Factor Authentication Configuration
    public bool? RequireMfa { get; set; }
    public int? MfaGracePeriodMinutes { get; set; }
    public string? AllowedMfaMethods { get; set; }
    public bool? RememberMfaForSession { get; set; }

    // Rate Limiting Configuration
    public int? RateLimitRequestsPerMinute { get; set; }
    public int? RateLimitRequestsPerHour { get; set; }
    public int? RateLimitRequestsPerDay { get; set; }

    // Branding & Customization Configuration
    public string? ThemeName { get; set; }
    public string? CustomCssUrl { get; set; }
    public string? CustomJavaScriptUrl { get; set; }
    public string? PageTitlePrefix { get; set; }
    public string? LogoUri { get; set; }
    public string? ClientUri { get; set; }
    public string? PolicyUri { get; set; }
    public string? TosUri { get; set; }

    // Logout & Integration Configuration
    public string? BackChannelLogoutUri { get; set; }
    public bool? BackChannelLogoutSessionRequired { get; set; }
    public string? FrontChannelLogoutUri { get; set; }
    public bool? FrontChannelLogoutSessionRequired { get; set; }
    public string? AllowedCorsOrigins { get; set; }
    public string? AllowedIdentityProviders { get; set; }

    // Advanced Configuration
    public string? ProtocolType { get; set; }
    public bool? EnableDetailedErrors { get; set; }
    public bool? LogSensitiveData { get; set; }
    public bool? EnableLocalLogin { get; set; }
    public string? CustomLoginPageUrl { get; set; }
    public string? CustomLogoutPageUrl { get; set; }
    public string? CustomErrorPageUrl { get; set; }

    // Login options (new)
    public bool? AllowPasskeyLogin { get; set; }
    public bool? AllowQrLoginQuick { get; set; }
    public bool? AllowQrLoginSecure { get; set; }
    public bool? AllowCodeLogin { get; set; }
}