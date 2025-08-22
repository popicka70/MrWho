namespace MrWho.ClientAuth;

public static class MrWhoClientAuthDefaults
{
    public const string CookieScheme = "MrWho.ClientAuth.Cookies";
    public const string OpenIdConnectScheme = "MrWho.ClientAuth.OIDC";
    public const string TokenHttpClientName = "MrWho.TokenClient"; // NEW: used for M2M token acquisition

    public static string BuildCookieScheme(string clientId) => $"MrWho.{clientId}.Cookies";
    public static string BuildOidcScheme(string clientId) => $"MrWho.{clientId}.OIDC";
}
