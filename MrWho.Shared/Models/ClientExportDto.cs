using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// JSON-exportable representation of a client. Does not include database IDs or secrets.
/// </summary>
public class ClientExportDto
{
    // Natural keys and identity
    public string ClientId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public ClientType ClientType { get; set; } = ClientType.Confidential;

    // Which realm this client belongs to (by name, not id)
    public string RealmName { get; set; } = string.Empty;

    // Flows
    public bool AllowAuthorizationCodeFlow { get; set; }
    public bool AllowClientCredentialsFlow { get; set; }
    public bool AllowPasswordFlow { get; set; }
    public bool AllowRefreshTokenFlow { get; set; }
    public bool RequirePkce { get; set; }
    public bool RequireClientSecret { get; set; }

    // Token lifetimes
    public TimeSpan? AccessTokenLifetime { get; set; }
    public TimeSpan? RefreshTokenLifetime { get; set; }
    public TimeSpan? AuthorizationCodeLifetime { get; set; }
    public int? IdTokenLifetimeMinutes { get; set; }
    public int? DeviceCodeLifetimeMinutes { get; set; }

    // Session & Cookies
    public int? SessionTimeoutHours { get; set; }
    public bool? UseSlidingSessionExpiration { get; set; }
    public int? RememberMeDurationDays { get; set; }
    public bool? RequireHttpsForCookies { get; set; }
    public string? CookieSameSitePolicy { get; set; }

    // Security & Compliance
    public bool? RequireConsent { get; set; }
    public bool? AllowRememberConsent { get; set; }
    public int? MaxRefreshTokensPerUser { get; set; }
    public bool? UseOneTimeRefreshTokens { get; set; }
    public bool? IncludeJwtId { get; set; }
    public bool? AlwaysSendClientClaims { get; set; }
    public bool? AlwaysIncludeUserClaimsInIdToken { get; set; }
    public string? ClientClaimsPrefix { get; set; }

    // Endpoints access
    public bool? AllowAccessToUserInfoEndpoint { get; set; }
    public bool? AllowAccessToIntrospectionEndpoint { get; set; }
    public bool? AllowAccessToRevocationEndpoint { get; set; }

    // Rate limiting
    public int? RateLimitRequestsPerMinute { get; set; }
    public int? RateLimitRequestsPerHour { get; set; }
    public int? RateLimitRequestsPerDay { get; set; }

    // Branding & customization
    public string? ThemeName { get; set; }
    public string? CustomCssUrl { get; set; }
    public string? CustomJavaScriptUrl { get; set; }
    public string? PageTitlePrefix { get; set; }
    public string? LogoUri { get; set; }
    public string? ClientUri { get; set; }
    public string? PolicyUri { get; set; }
    public string? TosUri { get; set; }

    // Logout integration
    public string? BackChannelLogoutUri { get; set; }
    public bool? BackChannelLogoutSessionRequired { get; set; }
    public string? FrontChannelLogoutUri { get; set; }
    public bool? FrontChannelLogoutSessionRequired { get; set; }

    // CORS & IdP
    public string? AllowedCorsOrigins { get; set; }
    public string? AllowedIdentityProviders { get; set; }

    // Protocol/advanced
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

    // Collections
    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutUris { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
    public List<string> Audiences { get; set; } = new();

    // Assigned users (portable references - no DB IDs)
    public List<ClientAssignedUserRef> AssignedUsers { get; set; } = new();

    // Metadata
    public string ExportedBy { get; set; } = "System";
    public DateTime ExportedAtUtc { get; set; } = DateTime.UtcNow;
    public string FormatVersion { get; set; } = "1.1";
}

/// <summary>
/// Portable reference to a user for client assignment import/export.
/// Prefer matching by UserName; fall back to Email if provided.
/// </summary>
public class ClientAssignedUserRef
{
    public string? UserName { get; set; }
    public string? Email { get; set; }
}
