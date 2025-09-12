using MrWho.Shared;

namespace MrWho.Shared.Models;

/// <summary>
/// DTO for realm data
/// </summary>
public class RealmDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? DisplayName { get; set; }
    public TimeSpan AccessTokenLifetime { get; set; } = MrWhoConstants.TokenLifetimes.AccessToken;
    public TimeSpan RefreshTokenLifetime { get; set; } = MrWhoConstants.TokenLifetimes.RefreshToken;
    public TimeSpan AuthorizationCodeLifetime { get; set; } = MrWhoConstants.TokenLifetimes.AuthorizationCode;
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public int ClientCount { get; set; }

    // === REALM DEFAULT CONFIGURATION PARAMETERS ===

    // Session & Cookie Defaults
    public int DefaultSessionTimeoutHours { get; set; } = 8;
    public int DefaultRememberMeDurationDays { get; set; } = 30;
    public bool DefaultUseSlidingSessionExpiration { get; set; } = true;
    public string DefaultCookieSameSitePolicy { get; set; } = "Lax";
    public bool DefaultRequireHttpsForCookies { get; set; } = false;

    // Security & Compliance Defaults
    public bool DefaultRequireConsent { get; set; } = false;
    public bool DefaultAllowRememberConsent { get; set; } = true;
    public int? DefaultMaxRefreshTokensPerUser { get; set; }
    public bool DefaultUseOneTimeRefreshTokens { get; set; } = false;
    public bool DefaultIncludeJwtId { get; set; } = true;

    // MFA Defaults
    public bool DefaultRequireMfa { get; set; } = false;
    public int? DefaultMfaGracePeriodMinutes { get; set; }
    public string? DefaultAllowedMfaMethods { get; set; }
    public bool DefaultRememberMfaForSession { get; set; } = true;

    // Rate Limiting Defaults
    public int? DefaultRateLimitRequestsPerMinute { get; set; }
    public int? DefaultRateLimitRequestsPerHour { get; set; }
    public int? DefaultRateLimitRequestsPerDay { get; set; }

    // Error Handling & Logging Defaults
    public bool DefaultEnableDetailedErrors { get; set; } = false;
    public bool DefaultLogSensitiveData { get; set; } = false;

    // Branding Defaults
    public string? DefaultThemeName { get; set; }

    // Realm-specific URLs and branding
    public string? RealmCustomCssUrl { get; set; }
    public string? RealmLogoUri { get; set; }
    public string? RealmUri { get; set; }
    public string? RealmPolicyUri { get; set; }
    public string? RealmTosUri { get; set; }

    // === PHASE 1.5: JAR / JARM REALM DEFAULTS ===
    public JarMode? DefaultJarMode { get; set; }
    public JarmMode? DefaultJarmMode { get; set; }
    public bool? DefaultRequireSignedRequestObject { get; set; }
    public string? DefaultAllowedRequestObjectAlgs { get; set; }
}