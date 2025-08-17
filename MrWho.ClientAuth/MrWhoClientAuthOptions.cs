using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace MrWho.ClientAuth;

/// <summary>
/// Options used to configure client applications that authenticate against the MrWho OIDC server.
/// </summary>
public sealed class MrWhoClientAuthOptions
{
    /// <summary>
    /// Client identifier registered at the MrWho Identity Server.
    /// Also used to derive distinct cookie and OIDC scheme names:
    /// MrWho.{ClientId}.Cookies and MrWho.{ClientId}.OIDC
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// The authority (base URL) of the MrWho Identity Server, e.g. https://localhost:7113
    /// Must be the externally reachable address for browser redirects.
    /// </summary>
    public string Authority { get; set; } = "https://localhost:7113";

    /// <summary>
    /// Optional explicit metadata address for back-channel discovery when Authority differs
    /// from the internal service address (Docker/Kubernetes). If not set, defaults to
    /// Authority + "/.well-known/openid-configuration".
    /// </summary>
    public string? MetadataAddress { get; set; }

    /// <summary>
    /// Client secret (for confidential clients). Leave null for public clients.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Scopes to request. Defaults to the recommended set used by MrWho for user apps.
    /// </summary>
    public IList<string> Scopes { get; } = new List<string>
    {
        "openid",
        "profile",
        "email",
        "roles",
        "offline_access",
        "api.read",
        "api.write"
        // NOTE: admin-only scope "mrwho.use" is intentionally not included by default
    };

    /// <summary>
    /// Whether to use PKCE. Enabled by default.
    /// </summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>
    /// Whether HTTPS is required for the metadata endpoint. Defaults according to Authority scheme.
    /// </summary>
    public bool? RequireHttpsMetadata { get; set; }

    /// <summary>
    /// If true, the back-channel HTTP handler will trust any server certificate.
    /// Only enable for development.
    /// </summary>
    public bool AllowSelfSignedCertificates { get; set; }

    /// <summary>
    /// Override for the cookie scheme name. If not set, defaults to MrWho.{ClientId}.Cookies (or
    /// MrWho.ClientAuth.Cookies when ClientId is empty).
    /// </summary>
    public string? CookieScheme { get; set; }

    /// <summary>
    /// Whether to save tokens in the auth session (access/refresh/id tokens). Enabled by default.
    /// </summary>
    public bool SaveTokens { get; set; } = true;

    /// <summary>
    /// Whether the UserInfo endpoint should be called after authentication. Defaults to false as many
    /// apps rely on ID token claims and to avoid 403 issues when scopes are limited.
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; set; } = false;

    /// <summary>
    /// Optional callback paths. If null, framework defaults are used.
    /// </summary>
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    public string RemoteSignOutPath { get; set; } = "/signout-oidc";

    /// <summary>
    /// Optional extra configuration hook for OpenIdConnectOptions.
    /// </summary>
    public Action<OpenIdConnectOptions>? ConfigureOpenIdConnect { get; set; }

    internal string ResolveMetadataAddress()
    {
        if (!string.IsNullOrWhiteSpace(MetadataAddress))
            return MetadataAddress!;

        // ALWAYS use the standard .well-known path with hyphens
        var baseUrl = Authority.TrimEnd('/');
        return $"{baseUrl}/.well-known/openid-configuration";
    }
}
