using System.Text.Json.Serialization;

namespace MrWho.Shared.Models;

/// <summary>
/// JSON-exportable representation of a realm. Does not include database IDs.
/// </summary>
public class RealmExportDto
{
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;

    // Token lifetimes
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    // Defaults
    public int DefaultSessionTimeoutHours { get; set; } = 8;
    public bool DefaultUseSlidingSessionExpiration { get; set; } = true;
    public int DefaultRememberMeDurationDays { get; set; } = 30;
    public bool DefaultRequireHttpsForCookies { get; set; } = false;
    public string DefaultCookieSameSitePolicy { get; set; } = "Lax";

    public bool DefaultRequireConsent { get; set; } = false;
    public bool DefaultAllowRememberConsent { get; set; } = true;
    public int? DefaultMaxRefreshTokensPerUser { get; set; }
    public bool DefaultUseOneTimeRefreshTokens { get; set; } = false;
    public bool DefaultIncludeJwtId { get; set; } = true;

    public bool DefaultRequireMfa { get; set; } = false;
    public int? DefaultMfaGracePeriodMinutes { get; set; }
    public string? DefaultAllowedMfaMethods { get; set; }
    public bool DefaultRememberMfaForSession { get; set; } = true;

    public int? DefaultRateLimitRequestsPerMinute { get; set; }
    public int? DefaultRateLimitRequestsPerHour { get; set; }
    public int? DefaultRateLimitRequestsPerDay { get; set; }

    public bool DefaultEnableDetailedErrors { get; set; } = false;
    public bool DefaultLogSensitiveData { get; set; } = false;

    public string? DefaultThemeName { get; set; }

    public string? RealmCustomCssUrl { get; set; }
    public string? RealmLogoUri { get; set; }
    public string? RealmUri { get; set; }
    public string? RealmPolicyUri { get; set; }
    public string? RealmTosUri { get; set; }

    // Exported clients belonging to this realm (optional)
    public List<ClientExportDto> Clients { get; set; } = new();

    // Exported scopes belonging to this system (realm-agnostic but included for convenience)
    public List<ScopeExportDto> Scopes { get; set; } = new();

    // Exported roles and users (portable)
    public List<RoleExportDto> Roles { get; set; } = new();
    public List<UserExportDto> Users { get; set; } = new();

    // Metadata
    public string ExportedBy { get; set; } = "System";
    public DateTime ExportedAtUtc { get; set; } = DateTime.UtcNow;
    public string FormatVersion { get; set; } = "1.0";
}
