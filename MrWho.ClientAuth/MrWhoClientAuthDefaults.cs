namespace MrWho.ClientAuth;

public static class MrWhoClientAuthDefaults
{
    public const string CookieScheme = "MrWho.ClientAuth.Cookies";
    public const string OpenIdConnectScheme = "OpenIdConnect"; // standard scheme key

    public static string BuildCookieScheme(string key)
        => $"MrWho.{Sanitize(key)}.Cookies";

    public static string BuildOidcScheme(string key)
        => $"MrWho.{Sanitize(key)}.OIDC";

    private static string Sanitize(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "Default";
        Span<char> buffer = stackalloc char[name.Length];
        int i = 0;
        foreach (var ch in name)
        {
            buffer[i++] = (char)(
                char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-' ? ch : '_'
            );
        }
        return new string(buffer[..i]);
    }
}
