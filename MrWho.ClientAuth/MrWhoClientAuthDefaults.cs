namespace MrWho.ClientAuth;

public static class MrWhoClientAuthDefaults
{
    public const string CookieScheme = "MrWho.ClientAuth.Cookies";
    public const string OpenIdConnectScheme = "OpenIdConnect"; // standard scheme key

    public static string BuildCookieScheme(string name)
        => $"MrWho.{Sanitize(name)}.Cookies";

    public static string BuildOidcScheme(string name)
        => $"MrWho.{Sanitize(name)}.OIDC";

    private static string Sanitize(string name)
        => string.IsNullOrWhiteSpace(name) ? "Default" : name.Replace(' ', '_');
}
