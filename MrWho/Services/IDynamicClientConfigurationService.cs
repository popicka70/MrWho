using Microsoft.AspNetCore.Authentication.Cookies;
using MrWho.Models;

namespace MrWho.Services;

/// <summary>
/// Service for applying dynamic client configuration parameters at runtime
/// </summary>
public interface IDynamicClientConfigurationService
{
    /// <summary>
    /// Gets dynamic cookie authentication options for a specific client
    /// </summary>
    Task<CookieAuthenticationOptions> GetClientCookieOptionsAsync(string clientId);
    
    /// <summary>
    /// Gets dynamic OpenIddict token lifetimes for a specific client
    /// </summary>
    Task<ClientTokenConfiguration> GetClientTokenConfigurationAsync(string clientId);
    
    /// <summary>
    /// Gets dynamic security configuration for a specific client
    /// </summary>
    Task<ClientSecurityConfiguration> GetClientSecurityConfigurationAsync(string clientId);
    
    /// <summary>
    /// Gets dynamic MFA configuration for a specific client
    /// </summary>
    Task<ClientMfaConfiguration> GetClientMfaConfigurationAsync(string clientId);
    
    /// <summary>
    /// Gets dynamic rate limiting configuration for a specific client
    /// </summary>
    Task<ClientRateLimitConfiguration> GetClientRateLimitConfigurationAsync(string clientId);
    
    /// <summary>
    /// Gets dynamic branding configuration for a specific client
    /// </summary>
    Task<ClientBrandingConfiguration> GetClientBrandingConfigurationAsync(string clientId);
    
    /// <summary>
    /// Applies all dynamic configurations to cookie options
    /// </summary>
    Task<CookieAuthenticationOptions> ApplyDynamicConfigurationAsync(Client client, CookieAuthenticationOptions options);
    
    /// <summary>
    /// Gets the effective configuration value with proper fallback hierarchy
    /// </summary>
    T GetEffectiveValue<T>(T? clientValue, T? realmDefault, T systemDefault);
}

/// <summary>
/// Dynamic token configuration for a client
/// </summary>
public class ClientTokenConfiguration
{
    public TimeSpan AccessTokenLifetime { get; set; }
    public TimeSpan RefreshTokenLifetime { get; set; }
    public TimeSpan AuthorizationCodeLifetime { get; set; }
    public TimeSpan IdTokenLifetime { get; set; }
    public TimeSpan DeviceCodeLifetime { get; set; }
    public bool UseOneTimeRefreshTokens { get; set; }
    public int? MaxRefreshTokensPerUser { get; set; }
    public string AccessTokenType { get; set; } = "JWT";
    public bool HashAccessTokens { get; set; }
    public bool UpdateAccessTokenClaimsOnRefresh { get; set; }
}

/// <summary>
/// Dynamic security configuration for a client
/// </summary>
public class ClientSecurityConfiguration
{
    public bool RequireConsent { get; set; }
    public bool AllowRememberConsent { get; set; }
    public bool RequireHttpsForCookies { get; set; }
    public SameSiteMode CookieSameSitePolicy { get; set; }
    public bool IncludeJwtId { get; set; }
    public bool AlwaysSendClientClaims { get; set; }
    public bool AlwaysIncludeUserClaimsInIdToken { get; set; }
    public bool EnableDetailedErrors { get; set; }
    public bool LogSensitiveData { get; set; }
    public bool AllowAccessToUserInfoEndpoint { get; set; } = true;
    public bool AllowAccessToIntrospectionEndpoint { get; set; } = false;
    public bool AllowAccessToRevocationEndpoint { get; set; } = true;
}

/// <summary>
/// Dynamic MFA configuration for a client
/// </summary>
public class ClientMfaConfiguration
{
    public bool RequireMfa { get; set; }
    public int? MfaGracePeriodMinutes { get; set; }
    public List<string> AllowedMfaMethods { get; set; } = new();
    public bool RememberMfaForSession { get; set; } = true;
}

/// <summary>
/// Dynamic rate limiting configuration for a client
/// </summary>
public class ClientRateLimitConfiguration
{
    public int? RequestsPerMinute { get; set; }
    public int? RequestsPerHour { get; set; }
    public int? RequestsPerDay { get; set; }
    public bool IsRateLimited => RequestsPerMinute.HasValue || RequestsPerHour.HasValue || RequestsPerDay.HasValue;
}

/// <summary>
/// Dynamic branding configuration for a client
/// </summary>
public class ClientBrandingConfiguration
{
    public string? ThemeName { get; set; }
    public string? CustomCssUrl { get; set; }
    public string? CustomJavaScriptUrl { get; set; }
    public string? LogoUri { get; set; }
    public string? ClientUri { get; set; }
    public string? PolicyUri { get; set; }
    public string? TosUri { get; set; }
    public string? PageTitlePrefix { get; set; }
    public string? CustomErrorPageUrl { get; set; }
    public string? CustomLoginPageUrl { get; set; }
    public string? CustomLogoutPageUrl { get; set; }
}