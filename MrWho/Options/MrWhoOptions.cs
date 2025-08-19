namespace MrWho.Options;

public class MrWhoOptions
{
    public CookieSeparationMode CookieSeparationMode { get; set; } = CookieSeparationMode.ByClient;

    // Server-level default UI theme (e.g., "light", "dark", "corporate", "ocean")
    public string? DefaultThemeName { get; set; } = "light"; // Fallback when client/realm not set
}

public enum CookieSeparationMode
{
    None = 0,
    ByClient = 1,
    ByRealm = 2
}
