namespace MrWho.Options;

public class MrWhoOptions
{
    public CookieSeparationMode CookieSeparationMode { get; set; } = CookieSeparationMode.ByClient;

    // Server-level default UI theme (e.g., "light", "dark", "corporate", "ocean")
    public string? DefaultThemeName { get; set; } = "light"; // Fallback when client/realm not set

    // ================= Device Auto-Login (trusted device cookie) =================
    /// <summary>
    /// Enables issuing and validating device auto-login cookies.
    /// </summary>
    public bool EnableDeviceAutoLogin { get; set; } = true;

    /// <summary>
    /// Default lifetime (days) for non-trusted devices.
    /// </summary>
    public int DeviceAutoLoginDefaultDays { get; set; } = 30;

    /// <summary>
    /// Lifetime (days) for trusted devices (IsTrusted=true).
    /// </summary>
    public int DeviceAutoLoginTrustedDays { get; set; } = 90;

    /// <summary>
    /// Maximum validation attempts allowed per minute per remote IP (basic throttle).
    /// </summary>
    public int DeviceAutoLoginMaxAttemptsPerMinute { get; set; } = 60;

    /// <summary>
    /// If true, rotate (issue new) token on every successful auto-login to limit replay window.
    /// </summary>
    public bool DeviceAutoLoginRotateOnUse { get; set; } = true;
}

public enum CookieSeparationMode
{
    None = 0,
    ByClient = 1,
    ByRealm = 2
}
