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

    /// <summary>
    /// If true, a resolved PAR entry (request_uri) is marked consumed and cannot be used again.
    /// If false, reuse is allowed until expiration.
    /// </summary>
    public bool ParSingleUseDefault { get; set; } = true;

    /// <summary>
    /// If true, enabling adapter reuse hashing/logging metrics (future PJ51) even when single-use.
    /// </summary>
    public bool ParEnableReuseMetrics { get; set; } = true;
}

public enum JarHandlerMode
{
    BuiltIn = 0,
    CustomExclusive = 1
}
