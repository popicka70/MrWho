using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using System.Runtime.Intrinsics.Arm;
using System.Text.Json;

namespace MrWho.Services;

/// <summary>
/// Implementation of dynamic client configuration service
/// </summary>
public class DynamicClientConfigurationService : IDynamicClientConfigurationService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<DynamicClientConfigurationService> _logger;

    public DynamicClientConfigurationService(
        ApplicationDbContext context, 
        ILogger<DynamicClientConfigurationService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<CookieAuthenticationOptions> GetClientCookieOptionsAsync(string clientId)
    {
        var client = await GetClientWithRealmAsync(clientId);
        if (client == null)
        {
            _logger.LogWarning("?? Client {ClientId} not found, using default cookie options", clientId);
            return CreateDefaultCookieOptions(clientId);
        }

        return await ApplyDynamicConfigurationAsync(client, CreateDefaultCookieOptions(clientId));
    }

    public async Task<ClientTokenConfiguration> GetClientTokenConfigurationAsync(string clientId)
    {
        var client = await GetClientWithRealmAsync(clientId);
        if (client == null)
        {
            return CreateDefaultTokenConfiguration();
        }

        return new ClientTokenConfiguration
        {
            AccessTokenLifetime = client.GetEffectiveAccessTokenLifetime(),
            RefreshTokenLifetime = client.GetEffectiveRefreshTokenLifetime(),
            AuthorizationCodeLifetime = client.GetEffectiveAuthorizationCodeLifetime(),
            IdTokenLifetime = GetEffectiveTimeSpanValue(
                client.IdTokenLifetimeMinutes.HasValue ? TimeSpan.FromMinutes(client.IdTokenLifetimeMinutes.Value) : null,
                client.Realm?.IdTokenLifetime,
                TimeSpan.FromMinutes(60)),
            DeviceCodeLifetime = GetEffectiveTimeSpanValue(
                client.DeviceCodeLifetimeMinutes.HasValue ? TimeSpan.FromMinutes(client.DeviceCodeLifetimeMinutes.Value) : null,
                client.Realm?.DeviceCodeLifetime,
                TimeSpan.FromMinutes(10)),
            UseOneTimeRefreshTokens = GetEffectiveBoolValue(
                client.UseOneTimeRefreshTokens,
                client.Realm?.DefaultUseOneTimeRefreshTokens,
                false),
            MaxRefreshTokensPerUser = GetEffectiveValue(
                client.MaxRefreshTokensPerUser,
                client.Realm?.DefaultMaxRefreshTokensPerUser,
                null),
            AccessTokenType = GetEffectiveValue(
                client.AccessTokenType,
                null,
                "JWT"),
            HashAccessTokens = GetEffectiveBoolValue(
                client.HashAccessTokens,
                null,
                false),
            UpdateAccessTokenClaimsOnRefresh = GetEffectiveBoolValue(
                client.UpdateAccessTokenClaimsOnRefresh,
                null,
                false)
        };
    }

    public async Task<ClientSecurityConfiguration> GetClientSecurityConfigurationAsync(string clientId)
    {
        var client = await GetClientWithRealmAsync(clientId);
        if (client == null)
        {
            return CreateDefaultSecurityConfiguration();
        }

        return new ClientSecurityConfiguration
        {
            RequireConsent = GetEffectiveBoolValue(
                client.RequireConsent,
                client.Realm?.DefaultRequireConsent,
                false),
            AllowRememberConsent = GetEffectiveBoolValue(
                client.AllowRememberConsent,
                client.Realm?.DefaultAllowRememberConsent,
                true),
            RequireHttpsForCookies = GetEffectiveBoolValue(
                client.RequireHttpsForCookies,
                client.Realm?.DefaultRequireHttpsForCookies,
                false),
            CookieSameSitePolicy = GetEffectiveCookieSameSitePolicy(client),
            IncludeJwtId = GetEffectiveBoolValue(
                client.IncludeJwtId,
                client.Realm?.DefaultIncludeJwtId,
                true),
            AlwaysSendClientClaims = GetEffectiveBoolValue(
                client.AlwaysSendClientClaims,
                null,
                false),
            AlwaysIncludeUserClaimsInIdToken = GetEffectiveBoolValue(
                client.AlwaysIncludeUserClaimsInIdToken,
                null,
                false),
            EnableDetailedErrors = GetEffectiveBoolValue(
                client.EnableDetailedErrors,
                client.Realm?.DefaultEnableDetailedErrors,
                false),
            LogSensitiveData = GetEffectiveBoolValue(
                client.LogSensitiveData,
                client.Realm?.DefaultLogSensitiveData,
                false),
            AllowAccessToUserInfoEndpoint = GetEffectiveBoolValue(
                client.AllowAccessToUserInfoEndpoint,
                null,
                true),
            AllowAccessToIntrospectionEndpoint = GetEffectiveBoolValue(
                client.AllowAccessToIntrospectionEndpoint,
                null,
                false),
            AllowAccessToRevocationEndpoint = GetEffectiveBoolValue(
                client.AllowAccessToRevocationEndpoint,
                null,
                true)
        };
    }

    public async Task<ClientMfaConfiguration> GetClientMfaConfigurationAsync(string clientId)
    {
        var client = await GetClientWithRealmAsync(clientId);
        if (client == null)
        {
            return CreateDefaultMfaConfiguration();
        }

        return new ClientMfaConfiguration
        {
            RequireMfa = GetEffectiveBoolValue(
                client.RequireMfa,
                client.Realm?.DefaultRequireMfa,
                false),
            MfaGracePeriodMinutes = GetEffectiveValue(
                client.MfaGracePeriodMinutes,
                client.Realm?.DefaultMfaGracePeriodMinutes,
                null),
            AllowedMfaMethods = GetEffectiveMfaMethods(client),
            RememberMfaForSession = GetEffectiveBoolValue(
                client.RememberMfaForSession,
                client.Realm?.DefaultRememberMfaForSession,
                true)
        };
    }

    public async Task<ClientRateLimitConfiguration> GetClientRateLimitConfigurationAsync(string clientId)
    {
        var client = await GetClientWithRealmAsync(clientId);
        if (client == null)
        {
            return CreateDefaultRateLimitConfiguration();
        }

        return new ClientRateLimitConfiguration
        {
            RequestsPerMinute = GetEffectiveValue(
                client.RateLimitRequestsPerMinute,
                client.Realm?.DefaultRateLimitRequestsPerMinute,
                null),
            RequestsPerHour = GetEffectiveValue(
                client.RateLimitRequestsPerHour,
                client.Realm?.DefaultRateLimitRequestsPerHour,
                null),
            RequestsPerDay = GetEffectiveValue(
                client.RateLimitRequestsPerDay,
                client.Realm?.DefaultRateLimitRequestsPerDay,
                null)
        };
    }

    public async Task<ClientBrandingConfiguration> GetClientBrandingConfigurationAsync(string clientId)
    {
        var client = await GetClientWithRealmAsync(clientId);
        if (client == null)
        {
            return CreateDefaultBrandingConfiguration();
        }

        return new ClientBrandingConfiguration
        {
            ThemeName = GetEffectiveValue(
                client.ThemeName,
                client.Realm?.DefaultThemeName,
                null),
            CustomCssUrl = GetEffectiveValue(
                client.CustomCssUrl,
                client.Realm?.RealmCustomCssUrl,
                null),
            CustomJavaScriptUrl = client.CustomJavaScriptUrl,
            LogoUri = GetEffectiveValue(
                client.LogoUri,
                client.Realm?.RealmLogoUri,
                null),
            ClientUri = GetEffectiveValue(
                client.ClientUri,
                client.Realm?.RealmUri,
                null),
            PolicyUri = GetEffectiveValue(
                client.PolicyUri,
                client.Realm?.RealmPolicyUri,
                null),
            TosUri = GetEffectiveValue(
                client.TosUri,
                client.Realm?.RealmTosUri,
                null),
            PageTitlePrefix = client.PageTitlePrefix,
            CustomErrorPageUrl = client.CustomErrorPageUrl,
            CustomLoginPageUrl = client.CustomLoginPageUrl,
            CustomLogoutPageUrl = client.CustomLogoutPageUrl
        };
    }

    public Task<CookieAuthenticationOptions> ApplyDynamicConfigurationAsync(
        Client client,
        CookieAuthenticationOptions options)
    {
        try
        {
            // Apply session timeout configuration
            var sessionHours = client.GetEffectiveSessionTimeoutHours();
            options.ExpireTimeSpan = TimeSpan.FromHours(sessionHours);

            // Apply sliding expiration configuration
            var useSlidingExpiration = GetEffectiveBoolValue(
                client.UseSlidingSessionExpiration,
                client.Realm?.DefaultUseSlidingSessionExpiration,
                true);
            options.SlidingExpiration = useSlidingExpiration;

            // Apply HTTPS requirement
            var requireHttps = GetEffectiveBoolValue(
                client.RequireHttpsForCookies,
                client.Realm?.DefaultRequireHttpsForCookies,
                false);
            options.Cookie.SecurePolicy = requireHttps ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;

            // Apply SameSite policy
            var sameSitePolicy = GetEffectiveCookieSameSitePolicy(client);
            options.Cookie.SameSite = sameSitePolicy;

            // Apply custom paths if configured
            if (!string.IsNullOrEmpty(client.CustomLoginPageUrl))
            {
                options.LoginPath = client.CustomLoginPageUrl;
            }

            if (!string.IsNullOrEmpty(client.CustomLogoutPageUrl))
            {
                options.LogoutPath = client.CustomLogoutPageUrl;
            }

            if (!string.IsNullOrEmpty(client.CustomErrorPageUrl))
            {
                options.AccessDeniedPath = client.CustomErrorPageUrl;
            }

            _logger.LogDebug("?? Applied dynamic configuration for client {ClientId}: Session={SessionHours}h, Sliding={Sliding}, HTTPS={RequireHttps}, SameSite={SameSite}", 
                client.ClientId, sessionHours, useSlidingExpiration, requireHttps, sameSitePolicy);

            return Task.FromResult(options);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "? Error applying dynamic configuration for client {ClientId}", client.ClientId);
            return Task.FromResult(options); // Return original options on error
        }
    }

    public T GetEffectiveValue<T>(T? clientValue, T? realmDefault, T systemDefault)
    {
        // Priority: Client-specific ? Realm default ? System default
        return clientValue ?? realmDefault ?? systemDefault;
    }

    private bool GetEffectiveBoolValue(bool? clientValue, bool? realmDefault, bool systemDefault)
    {
        return clientValue ?? realmDefault ?? systemDefault;
    }

    private TimeSpan GetEffectiveTimeSpanValue(TimeSpan? clientValue, TimeSpan? realmDefault, TimeSpan systemDefault)
    {
        return clientValue ?? realmDefault ?? systemDefault;
    }

    private async Task<Client?> GetClientWithRealmAsync(string clientId)
    {
        return await _context.Clients
            .Include(c => c.Realm)
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsEnabled);
    }

    private SameSiteMode GetEffectiveCookieSameSitePolicy(Client client)
    {
        var policy = GetEffectiveValue(
            client.CookieSameSitePolicy,
            client.Realm?.DefaultCookieSameSitePolicy,
            "Lax");

        return policy?.ToLowerInvariant() switch
        {
            "none" => SameSiteMode.None,
            "strict" => SameSiteMode.Strict,
            "lax" => SameSiteMode.Lax,
            _ => SameSiteMode.Lax
        };
    }

    private List<string> GetEffectiveMfaMethods(Client client)
    {
        var methods = GetEffectiveValue(
            client.AllowedMfaMethods,
            client.Realm?.DefaultAllowedMfaMethods,
            null);

        if (string.IsNullOrEmpty(methods))
        {
            return new List<string> { "totp", "sms" }; // Default methods
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(methods) ?? new List<string> { "totp", "sms" };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "?? Failed to parse MFA methods JSON for client {ClientId}, using defaults", client.ClientId);
            return new List<string> { "totp", "sms" };
        }
    }

    private static CookieAuthenticationOptions CreateDefaultCookieOptions(string clientId)
    {
        return new CookieAuthenticationOptions
        {
            Cookie = new CookieBuilder
            {
                Name = $".MrWho.{clientId}",
                HttpOnly = true,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                SameSite = SameSiteMode.Lax
            },
            ExpireTimeSpan = TimeSpan.FromHours(8),
            SlidingExpiration = true,
            LoginPath = "/connect/login",
            LogoutPath = "/connect/logout",
            AccessDeniedPath = "/connect/access-denied"
        };
    }

    private static ClientTokenConfiguration CreateDefaultTokenConfiguration()
    {
        return new ClientTokenConfiguration
        {
            AccessTokenLifetime = TimeSpan.FromMinutes(60),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(10),
            IdTokenLifetime = TimeSpan.FromMinutes(60),
            DeviceCodeLifetime = TimeSpan.FromMinutes(10),
            UseOneTimeRefreshTokens = false,
            AccessTokenType = "JWT",
            HashAccessTokens = false,
            UpdateAccessTokenClaimsOnRefresh = false
        };
    }

    private static ClientSecurityConfiguration CreateDefaultSecurityConfiguration()
    {
        return new ClientSecurityConfiguration
        {
            RequireConsent = false,
            AllowRememberConsent = true,
            RequireHttpsForCookies = false,
            CookieSameSitePolicy = SameSiteMode.Lax,
            IncludeJwtId = true,
            AlwaysSendClientClaims = false,
            AlwaysIncludeUserClaimsInIdToken = false,
            EnableDetailedErrors = false,
            LogSensitiveData = false,
            AllowAccessToUserInfoEndpoint = true,
            AllowAccessToIntrospectionEndpoint = false,
            AllowAccessToRevocationEndpoint = true
        };
    }

    private static ClientMfaConfiguration CreateDefaultMfaConfiguration()
    {
        return new ClientMfaConfiguration
        {
            RequireMfa = false,
            AllowedMfaMethods = new List<string> { "totp", "sms" },
            RememberMfaForSession = true
        };
    }

    private static ClientRateLimitConfiguration CreateDefaultRateLimitConfiguration()
    {
        return new ClientRateLimitConfiguration();
    }

    private static ClientBrandingConfiguration CreateDefaultBrandingConfiguration()
    {
        return new ClientBrandingConfiguration();
    }
}