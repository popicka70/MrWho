using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MrWho.Shared;

namespace MrWho.Models;

/// <summary>
/// Represents an OIDC client configuration
/// </summary>
public class Client
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [StringLength(200)]
    public string ClientId { get; set; } = string.Empty;

    [StringLength(500)]
    public string? ClientSecret { get; set; }

    [Required]
    [StringLength(200)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [Required]
    public bool IsEnabled { get; set; } = true;

    // Client type and flow settings
    public ClientType ClientType { get; set; } = ClientType.Confidential;
    public bool AllowAuthorizationCodeFlow { get; set; } = true;
    public bool AllowClientCredentialsFlow { get; set; } = false;
    public bool AllowPasswordFlow { get; set; } = false;
    public bool AllowRefreshTokenFlow { get; set; } = true;
    public bool RequirePkce { get; set; } = true;
    public bool RequireClientSecret { get; set; } = true;

    // =========================================================================
    // DYNAMIC TOKEN LIFETIME CONFIGURATION
    // =========================================================================
    
    /// <summary>Access token lifetime (null = use realm default)</summary>
    public TimeSpan? AccessTokenLifetime { get; set; }
    
    /// <summary>Refresh token lifetime (null = use realm default)</summary>
    public TimeSpan? RefreshTokenLifetime { get; set; }
    
    /// <summary>Authorization code lifetime (null = use realm default)</summary>
    public TimeSpan? AuthorizationCodeLifetime { get; set; }
    
    /// <summary>ID token lifetime in minutes (null = use default)</summary>
    public int? IdTokenLifetimeMinutes { get; set; }
    
    /// <summary>Device code lifetime in minutes (null = use default)</summary>
    public int? DeviceCodeLifetimeMinutes { get; set; }

    // ============================================================================
    // DYNAMIC SESSION & COOKIE CONFIGURATION  
    // ============================================================================
    
    /// <summary>Session timeout in hours (null = use default hardcoded logic)</summary>
    public int? SessionTimeoutHours { get; set; }
    
    /// <summary>Whether session should use sliding expiration</summary>
    public bool? UseSlidingSessionExpiration { get; set; }
    
    /// <summary>Remember me duration in days (null = use default)</summary>
    public int? RememberMeDurationDays { get; set; }
    
    /// <summary>Whether to require HTTPS for cookies</summary>
    public bool? RequireHttpsForCookies { get; set; }
    
    /// <summary>Cookie SameSite policy (None, Lax, Strict)</summary>
    [StringLength(20)]
    public string? CookieSameSitePolicy { get; set; }

    // ============================================================================
    // DYNAMIC SECURITY & COMPLIANCE CONFIGURATION
    // ============================================================================
    
    /// <summary>Whether consent is required for this client</summary>
    public bool? RequireConsent { get; set; }
    
    /// <summary>Whether to allow remembering consent</summary>
    public bool? AllowRememberConsent { get; set; }
    
    /// <summary>Maximum number of refresh tokens per user (null = unlimited)</summary>
    public int? MaxRefreshTokensPerUser { get; set; }
    
    /// <summary>Whether refresh tokens should be one-time use</summary>
    public bool? UseOneTimeRefreshTokens { get; set; }
    
    /// <summary>Whether to include JWT ID claim in access tokens</summary>
    public bool? IncludeJwtId { get; set; }
    
    /// <summary>Whether to always send client claims</summary>
    public bool? AlwaysSendClientClaims { get; set; }
    
    /// <summary>Whether to always include user claims in ID token</summary>
    public bool? AlwaysIncludeUserClaimsInIdToken { get; set; }

    // ============================================================================
    // DYNAMIC NETWORK & TIMEOUT CONFIGURATION
    // ============================================================================
    
    /// <summary>User code type for device flow (null = use default)</summary>
    [StringLength(50)]
    public string? UserCodeType { get; set; }
    
    /// <summary>Device flow polling interval in seconds (null = use default)</summary>
    public int? DeviceCodePollingIntervalSeconds { get; set; }
    
    /// <summary>Back-channel logout session required</summary>
    public bool? BackChannelLogoutSessionRequired { get; set; }
    
    /// <summary>Back-channel logout URI for this client</summary>
    [StringLength(2000)]
    public string? BackChannelLogoutUri { get; set; }
    
    /// <summary>Front-channel logout session required</summary>
    public bool? FrontChannelLogoutSessionRequired { get; set; }
    
    /// <summary>Front-channel logout URI for this client</summary>
    [StringLength(2000)]
    public string? FrontChannelLogoutUri { get; set; }

    // ============================================================================
    // DYNAMIC TOKEN FORMAT & VALIDATION CONFIGURATION
    // ============================================================================
    
    /// <summary>Access token type: JWT or Reference (null = use default)</summary>
    [StringLength(20)]
    public string? AccessTokenType { get; set; }
    
    /// <summary>Whether access token should be stored as hash</summary>
    public bool? HashAccessTokens { get; set; }
    
    /// <summary>Whether to update access token claims on refresh</summary>
    public bool? UpdateAccessTokenClaimsOnRefresh { get; set; }
    
    /// <summary>Allowed CORS origins (JSON array as string)</summary>
    [StringLength(4000)]
    public string? AllowedCorsOrigins { get; set; }
    
    /// <summary>Client claims prefix</summary>
    [StringLength(100)]
    public string? ClientClaimsPrefix { get; set; }
    
    /// <summary>Whether to pair-wise identify subjects for this client</summary>
    public bool? PairWiseSubjectSalt { get; set; }

    // ============================================================================
    // DYNAMIC API ACCESS & RATE LIMITING CONFIGURATION
    // ============================================================================
    
    /// <summary>Rate limit: max requests per minute (null = no limit)</summary>
    public int? RateLimitRequestsPerMinute { get; set; }
    
    /// <summary>Rate limit: max requests per hour (null = no limit)</summary>
    public int? RateLimitRequestsPerHour { get; set; }
    
    /// <summary>Rate limit: max requests per day (null = no limit)</summary>
    public int? RateLimitRequestsPerDay { get; set; }
    
    /// <summary>Whether client can access user info endpoint</summary>
    public bool? AllowAccessToUserInfoEndpoint { get; set; }
    
    /// <summary>Whether client can access token introspection endpoint</summary>
    public bool? AllowAccessToIntrospectionEndpoint { get; set; }
    
    /// <summary>Whether client can access token revocation endpoint</summary>
    public bool? AllowAccessToRevocationEndpoint { get; set; }

    // ============================================================================
    // DYNAMIC PROTOCOL & INTEGRATION CONFIGURATION
    // ============================================================================
    
    /// <summary>Supported protocol type (null = OIDC default)</summary>
    [StringLength(50)]
    public string? ProtocolType { get; set; }
    
    /// <summary>Whether to enable local login for this client</summary>
    public bool? EnableLocalLogin { get; set; }
    
    /// <summary>Allowed identity providers (JSON array as string)</summary>
    [StringLength(2000)]
    public string? AllowedIdentityProviders { get; set; }
    
    /// <summary>Whether client logo should be displayed</summary>
    public bool? ShowClientLogo { get; set; }
    
    /// <summary>Client logo URI</summary>
    [StringLength(2000)]
    public string? LogoUri { get; set; }
    
    /// <summary>Client homepage URI</summary>
    [StringLength(2000)]
    public string? ClientUri { get; set; }
    
    /// <summary>Client privacy policy URI</summary>
    [StringLength(2000)]
    public string? PolicyUri { get; set; }
    
    /// <summary>Client terms of service URI</summary>
    [StringLength(2000)]
    public string? TosUri { get; set; }

    // ============================================================================
    // DYNAMIC ERROR HANDLING & LOGGING CONFIGURATION
    // ============================================================================
    
    /// <summary>Whether to log detailed errors for this client</summary>
    public bool? EnableDetailedErrors { get; set; }
    
    /// <summary>Whether to log sensitive data for this client (dev only)</summary>
    public bool? LogSensitiveData { get; set; }
    
    /// <summary>Custom error page URL for this client</summary>
    [StringLength(2000)]
    public string? CustomErrorPageUrl { get; set; }
    
    /// <summary>Custom login page URL for this client</summary>
    [StringLength(2000)]
    public string? CustomLoginPageUrl { get; set; }
    
    /// <summary>Custom logout page URL for this client</summary>
    [StringLength(2000)]
    public string? CustomLogoutPageUrl { get; set; }

    // ============================================================================
    // DYNAMIC MULTI-FACTOR AUTHENTICATION CONFIGURATION
    // ============================================================================
    
    /// <summary>Whether MFA is required for this client</summary>
    public bool? RequireMfa { get; set; }
    
    /// <summary>MFA grace period in minutes (null = no grace period)</summary>
    public int? MfaGracePeriodMinutes { get; set; }
    
    /// <summary>Allowed MFA methods (JSON array as string)</summary>
    [StringLength(1000)]
    public string? AllowedMfaMethods { get; set; }
    
    /// <summary>Whether to remember MFA for session</summary>
    public bool? RememberMfaForSession { get; set; }

    // ============================================================================
    // DYNAMIC BRANDING & CUSTOMIZATION CONFIGURATION
    // ============================================================================
    
    /// <summary>Custom CSS URL for this client's login pages</summary>
    [StringLength(2000)]
    public string? CustomCssUrl { get; set; }
    
    /// <summary>Custom JavaScript URL for this client's pages</summary>
    [StringLength(2000)]
    public string? CustomJavaScriptUrl { get; set; }
    
    /// <summary>Theme name for this client (null = default theme)</summary>
    [StringLength(100)]
    public string? ThemeName { get; set; }
    
    /// <summary>Custom page title prefix for this client</summary>
    [StringLength(200)]
    public string? PageTitlePrefix { get; set; }

    // Audit fields
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }

    // Realm relationship
    [Required]
    public string RealmId { get; set; } = string.Empty;
    
    [ForeignKey(nameof(RealmId))]
    public virtual Realm Realm { get; set; } = null!;

    // Navigation properties
    public virtual ICollection<ClientRedirectUri> RedirectUris { get; set; } = new List<ClientRedirectUri>();
    public virtual ICollection<ClientPostLogoutUri> PostLogoutUris { get; set; } = new List<ClientPostLogoutUri>();
    public virtual ICollection<ClientScope> Scopes { get; set; } = new List<ClientScope>();
    public virtual ICollection<ClientPermission> Permissions { get; set; } = new List<ClientPermission>();

    // ============================================================================
    // HELPER METHODS FOR DYNAMIC CONFIGURATION
    // ============================================================================
    
    /// <summary>Gets the effective session timeout, falling back to realm or hardcoded defaults</summary>
    public int GetEffectiveSessionTimeoutHours()
    {
        if (SessionTimeoutHours.HasValue) return SessionTimeoutHours.Value;
        
        // Fallback to current hardcoded logic as default
        return ClientId switch
        {
            "mrwho_admin_web" => 8,    // Admin work day
            "mrwho_demo1" => 2,        // Demo session
            _ when ClientId.Contains("api") => 1,  // API clients
            _ when ClientId.Contains("mobile") => 4, // Mobile apps
            _ when ClientId.Contains("spa") => 2,    // SPAs
            _ => 8  // Default enterprise clients
        };
    }
    
    /// <summary>Gets the effective access token lifetime, with fallbacks</summary>
    public TimeSpan GetEffectiveAccessTokenLifetime()
    {
        return AccessTokenLifetime ?? Realm?.AccessTokenLifetime ?? TimeSpan.FromMinutes(60);
    }
    
    /// <summary>Gets the effective refresh token lifetime, with fallbacks</summary>
    public TimeSpan GetEffectiveRefreshTokenLifetime()
    {
        return RefreshTokenLifetime ?? Realm?.RefreshTokenLifetime ?? TimeSpan.FromDays(30);
    }
    
    /// <summary>Gets the effective authorization code lifetime, with fallbacks</summary>
    public TimeSpan GetEffectiveAuthorizationCodeLifetime()
    {
        return AuthorizationCodeLifetime ?? Realm?.AuthorizationCodeLifetime ?? TimeSpan.FromMinutes(10);
    }
}
