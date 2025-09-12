using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

/// <summary>
/// Request to update realm default configuration and branding
/// </summary>
public class UpdateRealmDefaultsRequest
{
    // Token Lifetime Defaults (realm-level)
    public TimeSpan AccessTokenLifetime { get; set; }
    public TimeSpan RefreshTokenLifetime { get; set; }
    public TimeSpan AuthorizationCodeLifetime { get; set; }
    public TimeSpan IdTokenLifetime { get; set; }
    public TimeSpan DeviceCodeLifetime { get; set; }

    // Session & Cookie Defaults
    public int DefaultSessionTimeoutHours { get; set; }
    public int DefaultRememberMeDurationDays { get; set; }
    public bool DefaultUseSlidingSessionExpiration { get; set; }
    [StringLength(20)]
    public string DefaultCookieSameSitePolicy { get; set; } = string.Empty;
    public bool DefaultRequireHttpsForCookies { get; set; }

    // Security & Compliance Defaults
    public bool DefaultRequireConsent { get; set; }
    public bool DefaultAllowRememberConsent { get; set; }
    public int? DefaultMaxRefreshTokensPerUser { get; set; }
    public bool DefaultUseOneTimeRefreshTokens { get; set; }
    public bool DefaultIncludeJwtId { get; set; }

    // MFA Defaults
    public bool DefaultRequireMfa { get; set; }
    public int? DefaultMfaGracePeriodMinutes { get; set; }
    [StringLength(1000)]
    public string? DefaultAllowedMfaMethods { get; set; }
    public bool DefaultRememberMfaForSession { get; set; }

    // Rate Limiting Defaults
    public int? DefaultRateLimitRequestsPerMinute { get; set; }
    public int? DefaultRateLimitRequestsPerHour { get; set; }
    public int? DefaultRateLimitRequestsPerDay { get; set; }

    // Error Handling & Logging Defaults
    public bool DefaultEnableDetailedErrors { get; set; }
    public bool DefaultLogSensitiveData { get; set; }

    // Branding & Realm info
    [StringLength(100)]
    public string? DefaultThemeName { get; set; }
    [StringLength(2000)]
    public string? RealmCustomCssUrl { get; set; }
    [StringLength(2000)]
    public string? RealmLogoUri { get; set; }
    [StringLength(2000)]
    public string? RealmUri { get; set; }
    [StringLength(2000)]
    public string? RealmPolicyUri { get; set; }
    [StringLength(2000)]
    public string? RealmTosUri { get; set; }

    // Phase 1.5 JAR/JARM defaults
    public JarMode? DefaultJarMode { get; set; }
    public JarmMode? DefaultJarmMode { get; set; }
    public bool? DefaultRequireSignedRequestObject { get; set; }
    [StringLength(400)]
    public string? DefaultAllowedRequestObjectAlgs { get; set; }
}
