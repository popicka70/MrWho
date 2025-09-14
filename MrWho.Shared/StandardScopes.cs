namespace MrWho.Shared;

/// <summary>
/// Standard OpenID Connect scopes
/// </summary>
public static class StandardScopes
{
    public const string OpenId = "openid";
    public const string Email = "email";
    public const string Profile = "profile";
    public const string Roles = "roles";
    public const string OfflineAccess = "offline_access";
    public const string ApiRead = "api.read";
    public const string ApiWrite = "api.write";
    public const string MrWhoUse = "mrwho.use";
}
