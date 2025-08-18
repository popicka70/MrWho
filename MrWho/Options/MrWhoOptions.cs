namespace MrWho.Options;

public class MrWhoOptions
{
    public CookieSeparationMode CookieSeparationMode { get; set; } = CookieSeparationMode.ByClient;
}

public enum CookieSeparationMode
{
    None = 0,
    ByClient = 1,
    ByRealm = 2
}
