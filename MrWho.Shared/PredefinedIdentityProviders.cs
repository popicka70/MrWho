namespace MrWho.Shared;

public record PredefinedIdentityProviderTemplate(
    string Key,
    string DisplayName,
    string Authority,
    string DefaultScopes = "openid profile email",
    int Order = 100
);

public static class PredefinedIdentityProviders
{
    public static readonly IReadOnlyList<PredefinedIdentityProviderTemplate> Templates = new List<PredefinedIdentityProviderTemplate>
    {
        new("google", "Google", "https://accounts.google.com", "openid profile email", 10),
        new("microsoft", "Microsoft (Entra ID)", "https://login.microsoftonline.com/common/v2.0", "openid profile email", 20),
        // Caution: the following providers expose OIDC discovery endpoints, but may require extra configuration.
        new("apple", "Apple", "https://appleid.apple.com", "openid name email", 30),
        new("gitlab", "GitLab (gitlab.com)", "https://gitlab.com", "openid profile email", 40)
    };
}
