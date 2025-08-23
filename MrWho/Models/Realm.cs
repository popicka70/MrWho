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
    
    /// <summary>Default access token lifetime for clients in this realm</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    
    /// <summary>Default refresh token lifetime for clients in this realm</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    
    /// <summary>Default authorization code lifetime for clients in this realm</summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    
    /// <summary>Default ID token lifetime for clients in this realm</summary>
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    
    /// <summary>Default device code lifetime for clients in this realm</summary>
    public TimeSpan DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    // ============================================================================
    // DEFAULT SESSION & SECURITY CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    
    /// <summary>Default session timeout in hours for clients in this realm</summary>
    public int DefaultSessionTimeoutHours { get; set; } = 8;
    
    /// <summary>Default sliding session expiration setting</summary>
    public bool DefaultUseSlidingSessionExpiration { get; set; } = true;
    
    /// <summary>Default remember me duration in days</summary>
    public int DefaultRememberMeDurationDays { get; set; } = 30;
    
    /// <summary>Default HTTPS requirement for cookies in this realm</summary>
    public bool DefaultRequireHttpsForCookies { get; set; } = false;
    
    /// <summary>Default cookie SameSite policy for this realm</summary>
    [StringLength(20)]
    public string DefaultCookieSameSitePolicy { get; set; } = "Lax";

    // ============================================================================
    // DEFAULT CONSENT & COMPLIANCE CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    
    /// <summary>Default consent requirement for clients in this realm</summary>
    public bool DefaultRequireConsent { get; set; } = false;
    
    /// <summary>Default setting for allowing remembering consent</summary>
    public bool DefaultAllowRememberConsent { get; set; } = true;
    
    /// <summary>Default maximum refresh tokens per user in this realm</summary>
    public int? DefaultMaxRefreshTokensPerUser { get; set; }
    
    /// <summary>Default setting for one-time refresh tokens</summary>
    public bool DefaultUseOneTimeRefreshTokens { get; set; } = false;
    
    /// <summary>Default setting for including JWT ID in access tokens</summary>
    public bool DefaultIncludeJwtId { get; set; } = true;

    // ============================================================================
    // DEFAULT MFA CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    
    /// <summary>Default MFA requirement for clients in this realm</summary>
    public bool DefaultRequireMfa { get; set; } = false;
    
    /// <summary>Default MFA grace period in minutes</summary>
    public int? DefaultMfaGracePeriodMinutes { get; set; }
    
    /// <summary>Default allowed MFA methods (JSON array as string)</summary>
    [StringLength(1000)]
    public string? DefaultAllowedMfaMethods { get; set; }
    
    /// <summary>Default setting for remembering MFA in session</summary>
    public bool DefaultRememberMfaForSession { get; set; } = true;

    // ============================================================================
    // DEFAULT RATE LIMITING CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    
    /// <summary>Default rate limit: max requests per minute</summary>
    public int? DefaultRateLimitRequestsPerMinute { get; set; }
    
    /// <summary>Default rate limit: max requests per hour</summary>
    public int? DefaultRateLimitRequestsPerHour { get; set; }
    
    /// <summary>Default rate limit: max requests per day</summary>
    public int? DefaultRateLimitRequestsPerDay { get; set; }

    // ============================================================================
    // DEFAULT LOGGING & ERROR HANDLING CONFIGURATION (REALM-LEVEL DEFAULTS)
    // ============================================================================
    
    /// <summary>Default setting for detailed error logging</summary>
    public bool DefaultEnableDetailedErrors { get; set; } = false;
    
    /// <summary>Default setting for sensitive data logging (dev only)</summary>
    public bool DefaultLogSensitiveData { get; set; } = false;

    // ============================================================================
    // REALM-LEVEL BRANDING & CUSTOMIZATION
    // ============================================================================
    
    /// <summary>Default theme for clients in this realm</summary>
    [StringLength(100)]
    public string? DefaultThemeName { get; set; }
    
    /// <summary>Realm logo URI</summary>
    [StringLength(2000)]
    public string? RealmLogoUri { get; set; }
    
    /// <summary>Realm home page URI</summary>
    [StringLength(2000)]
    public string? RealmUri { get; set; }
    
    /// <summary>Realm privacy policy URI</summary>
    [StringLength(2000)]
    public string? RealmPolicyUri { get; set; }
    
    /// <summary>Realm terms of service URI</summary>
    [StringLength(2000)]
    public string? RealmTosUri { get; set; }
    
    /// <summary>Custom CSS URL for realm-wide styling</summary>
    [StringLength(2000)]
    public string? RealmCustomCssUrl { get; set; }

    // Audit fields
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Navigation properties
    public virtual ICollection<Client> Clients { get; set; } = new List<Client>();

    // ============================================================================
    // HELPER METHODS FOR REALM DEFAULTS
    // ============================================================================
    
    /// <summary>Gets the effective cookie SameSite policy</summary>
    public SameSiteMode GetEffectiveCookieSameSitePolicy()
    {
        return DefaultCookieSameSitePolicy?.ToLowerInvariant() switch
        {
            "none" => SameSiteMode.None,
            "strict" => SameSiteMode.Strict,
            "lax" => SameSiteMode.Lax,
            _ => SameSiteMode.Lax
        };
    }
    
    /// <summary>Gets the allowed MFA methods as a list</summary>
    public List<string> GetAllowedMfaMethods()
    {
        if (string.IsNullOrEmpty(DefaultAllowedMfaMethods))
            return new List<string> { "totp", "sms" }; // Default methods
            
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<List<string>>(DefaultAllowedMfaMethods) ?? new List<string>();
        }
        catch
        {
            return new List<string> { "totp", "sms" }; // Fallback on parse error
        }
    }

    // ============================================================================
    // REALM-LEVEL AUDIENCE CONFIGURATION DEFAULTS
    // ============================================================================
    
    /// <summary>Default audience mode for clients in this realm</summary>
    public AudienceMode? AudienceMode { get; set; }
    
    /// <summary>Default primary audience identifier for clients in this realm</summary>
    [StringLength(200)]
    public string? PrimaryAudience { get; set; }
    
    /// <summary>Default setting for including audience in ID token</summary>
    public bool? IncludeAudInIdToken { get; set; }
    
    /// <summary>Default requirement for explicit audience scope</summary>
    public bool? RequireExplicitAudienceScope { get; set; }
}
