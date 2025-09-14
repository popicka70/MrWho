namespace MrWho.Shared.Constants;

/// <summary>
/// Common query string parameter names.
/// </summary>
public static class QueryParameterNames
{
    public const string ReturnUrl = "returnUrl";          // internal camelCase usage
    public const string ClientId = "clientId";            // internal camelCase usage
    public const string Missing = "missing";
    public const string Requested = "requested";

    // OIDC standard parameter names
    public const string OidcClientId = "client_id";       // standard snake_case form in OIDC specs
    public const string Scope = "scope";
    public const string Prompt = "prompt";
    public const string MaxAge = "max_age";
}
