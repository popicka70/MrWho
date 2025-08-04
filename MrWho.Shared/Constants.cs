using System.Text.Json.Serialization;

namespace MrWho.Shared;

/// <summary>
/// Client types for OpenIdConnect clients
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ClientType
{
    /// <summary>
    /// Confidential client - can securely store credentials
    /// </summary>
    Confidential = 0,
    
    /// <summary>
    /// Public client - cannot securely store credentials
    /// </summary>
    Public = 1,
    
    /// <summary>
    /// Machine-to-machine client
    /// </summary>
    Machine = 2
}

/// <summary>
/// Standard OpenID Connect scopes
/// </summary>
public static class StandardScopes
{
    public const string OpenId = "openid";
    public const string Email = "email";
    public const string Profile = "profile";
    public const string Roles = "roles";
    public const string ApiRead = "api.read";
    public const string ApiWrite = "api.write";
}

/// <summary>
/// Standard OpenID Connect permissions
/// </summary>
public static class StandardPermissions
{
    public const string ScopeOpenId = "oidc:scope:openid";
    public const string ScopeEmail = "oidc:scope:email";
    public const string ScopeProfile = "oidc:scope:profile";
    public const string ScopeRoles = "oidc:scope:roles";
    public const string ScopeApiRead = "oidc:scope:api.read";
    public const string ScopeApiWrite = "oidc:scope:api.write";
}

/// <summary>
/// Application-specific constants
/// </summary>
public static class MrWhoConstants
{
    public const string AdminRealmName = "admin";
    public const string DefaultRealmName = "default";
    public const string AdminClientId = "mrwho_admin_web";
    
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