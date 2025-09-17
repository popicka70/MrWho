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

    /// <summary>
    /// Query vs request object conflict detection (PJ40).
    /// Disabled by default for safe rollout.
    /// </summary>
    public RequestConflictOptions RequestConflicts { get; set; } = new() { Enabled = true };

    /// <summary>
    /// Claim / parameter limits (PJ41). Disabled (null/0) by default.
    /// </summary>
    public RequestLimitOptions RequestLimits { get; set; } = new();
}

public enum JarHandlerMode
{
    BuiltIn = 0,
    CustomExclusive = 1
}

public sealed class RequestConflictOptions
{
    /// <summary>
    /// Enable detection of differing values between raw query and JAR/PAR expanded parameters.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Parameters to ignore (case-insensitive). Defaults include 'request','request_uri','_par_resolved','_jar_validated'.
    /// </summary>
    public string[] IgnoredParameters { get; set; } = new[] { "request", "request_uri", "_par_resolved", "_jar_validated" };

    /// <summary>
    /// If true, treat scope ordering differences as a conflict. If false, ordering is normalized.
    /// </summary>
    public bool StrictScopeOrdering { get; set; } = false;
}

public sealed class RequestLimitOptions
{
    public int? MaxParameters { get; set; } = null; // total distinct parameter names
    public int? MaxParameterNameLength { get; set; } = null; // max chars per name
    public int? MaxParameterValueLength { get; set; } = null; // max chars per value
    public int? MaxAggregateValueBytes { get; set; } = null; // UTF8 sum
    public int? MaxScopeItems { get; set; } = null; // space-delimited scope tokens
    public int? MaxAcrValues { get; set; } = null; // space-delimited acr_values tokens
}
