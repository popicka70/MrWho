namespace MrWho.Options;

/// <summary>
/// Advanced OIDC feature toggles (custom JAR/JARM/PAR pipeline integration).
/// Bound from configuration section "OidcAdvanced" if present.
/// </summary>
public sealed class OidcAdvancedOptions
{
    /// <summary>
    /// Controls how JAR (request object) processing is performed.
    /// BuiltIn = let OpenIddict built-in handlers process the request object.
    /// CustomExclusive = custom early handler validates, merges and strips the original 'request' parameter so built-ins skip.
    /// </summary>
    public JarHandlerMode JarHandlerMode { get; set; } = JarHandlerMode.CustomExclusive;
}

public enum JarHandlerMode
{
    BuiltIn = 0,
    CustomExclusive = 1
}
