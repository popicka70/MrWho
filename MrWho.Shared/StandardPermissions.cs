namespace MrWho.Shared;

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
