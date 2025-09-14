namespace MrWho.Shared;

/// <summary>
/// Application-specific constants
/// </summary>
public static class MrWhoConstants
{
    public const string AdminRealmName = "admin";
    public const string DefaultRealmName = "default";
    public const string AdminClientId = "mrwho_admin_web";
    public const string ServiceM2MClientId = "mrwho_m2m"; // added for standard service machine client

    /// <summary>
    /// Default token lifetimes
    /// </summary>
    public static class TokenLifetimes
    {
        public static readonly TimeSpan AccessToken = TimeSpan.FromMinutes(60);
        public static readonly TimeSpan RefreshToken = TimeSpan.FromDays(30);
        public static readonly TimeSpan AuthorizationCode = TimeSpan.FromMinutes(10);
    }

    /// <summary>
    /// API endpoints
    /// </summary>
    public static class ApiEndpoints
    {
        public const string Realms = "api/realms";
        public const string Clients = "api/clients";
        public const string Users = "api/users";
    }

    /// <summary>
    /// Default redirect URIs for admin client
    /// </summary>
    public static class AdminClientDefaults
    {
        public static readonly string[] RedirectUris =
        {
            "https://localhost:7257/signin-oidc",
            "https://localhost:7257/callback"
        };

        public static readonly string[] PostLogoutUris =
        {
            "https://localhost:7257/",
            "https://localhost:7257/signout-callback-oidc"
        };

        public static readonly string[] Scopes =
        {
            StandardScopes.OpenId,
            StandardScopes.Email,
            StandardScopes.Profile,
            StandardScopes.Roles,
            StandardScopes.ApiRead,
            StandardScopes.ApiWrite
        };
    }
}
