using System.ComponentModel.DataAnnotations;
using MrWho.Shared;

namespace MrWho.Models;

/// <summary>
/// Represents a logical grouping/namespace for OIDC clients
/// </summary>
public class Realm
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [Required]
    public bool IsEnabled { get; set; } = true;

    [StringLength(500)]
    public string? DisplayName { get; set; }

    // ============================================================================
    // DEFAULT TOKEN LIFETIME CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    // ============================================================================
    // DEFAULT SESSION & SECURITY CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    public int DefaultSessionTimeoutHours { get; set; } = 8;
    public bool DefaultUseSlidingSessionExpiration { get; set; } = true;
    public int DefaultRememberMeDurationDays { get; set; } = 30;
    public bool DefaultRequireHttpsForCookies { get; set; } = false;
    [StringLength(20)] public string DefaultCookieSameSitePolicy { get; set; } = "Lax";

    // ============================================================================
    // DEFAULT CONSENT & COMPLIANCE CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    public bool DefaultRequireConsent { get; set; } = false;
    public bool DefaultAllowRememberConsent { get; set; } = true;
    public int? DefaultMaxRefreshTokensPerUser { get; set; }
    public bool DefaultUseOneTimeRefreshTokens { get; set; } = false;
    public bool DefaultIncludeJwtId { get; set; } = true;

    // ============================================================================
    // DEFAULT MFA CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    public bool DefaultRequireMfa { get; set; } = false;
    public int? DefaultMfaGracePeriodMinutes { get; set; }
    [StringLength(1000)] public string? DefaultAllowedMfaMethods { get; set; }
    public bool DefaultRememberMfaForSession { get; set; } = true;

    // ============================================================================
    // DEFAULT RATE LIMITING CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    public int? DefaultRateLimitRequestsPerMinute { get; set; }
    public int? DefaultRateLimitRequestsPerHour { get; set; }
    public int? DefaultRateLimitRequestsPerDay { get; set; }

    // ============================================================================
    // DEFAULT LOGGING & ERROR HANDLING CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    public bool DefaultEnableDetailedErrors { get; set; } = false;
    public bool DefaultLogSensitiveData { get; set; } = false;

    // ============================================================================
    // REALM-LEVEL BRANDING & CUSTOMIZATION
    // ============================================================================
    [StringLength(100)] public string? DefaultThemeName { get; set; }
    [StringLength(2000)] public string? RealmLogoUri { get; set; }
    [StringLength(2000)] public string? RealmUri { get; set; }
    [StringLength(2000)] public string? RealmPolicyUri { get; set; }
    [StringLength(2000)] public string? RealmTosUri { get; set; }
    [StringLength(2000)] public string? RealmCustomCssUrl { get; set; }

    // ============================================================================
    // REALM-LEVEL AUDIENCE CONFIGURATION DEFAULTS
    // ============================================================================
    public AudienceMode? AudienceMode { get; set; }
    [StringLength(200)] public string? PrimaryAudience { get; set; }
    public bool? IncludeAudInIdToken { get; set; }
    public bool? RequireExplicitAudienceScope { get; set; }

    // ============================================================================
    // PHASE 1.5 DEFAULTS FOR JAR / JARM (OPTIONAL)
    // ============================================================================
    public JarMode? DefaultJarMode { get; set; }
    public JarmMode? DefaultJarmMode { get; set; }
    public bool? DefaultRequireSignedRequestObject { get; set; }
    [StringLength(400)] public string? DefaultAllowedRequestObjectAlgs { get; set; }

    // Audit fields
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Navigation properties
    public virtual ICollection<Client> Clients { get; set; } = new List<Client>();

    // Helpers ---------------------------------------------------------------
    public SameSiteMode GetEffectiveCookieSameSitePolicy() => DefaultCookieSameSitePolicy?.ToLowerInvariant() switch
    {
        "none" => SameSiteMode.None,
        "strict" => SameSiteMode.Strict,
        "lax" => SameSiteMode.Lax,
        _ => SameSiteMode.Lax
    };

    public List<string> GetAllowedMfaMethods()
    {
        if (string.IsNullOrEmpty(DefaultAllowedMfaMethods)) {
            return new List<string> { "totp", "sms" };
        }

        try { return System.Text.Json.JsonSerializer.Deserialize<List<string>>(DefaultAllowedMfaMethods) ?? new(); }
        catch { return new List<string> { "totp", "sms" }; }
    }
}
