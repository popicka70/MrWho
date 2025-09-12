namespace MrWho.Options;

/// <summary>
/// Configuration for symmetric (HMAC) client secret length policy.
/// Values represent minimum number of bytes (UTF8) required for the shared secret
/// used with a given HMAC based JWS algorithm.
/// </summary>
public sealed class SymmetricSecretPolicyOptions
{
    public const string SectionName = "SymmetricSecretPolicy";

    /// <summary>Minimum bytes for HS256 (default 32)</summary>
    public int HS256MinBytes { get; set; } = 32;
    /// <summary>Minimum bytes for HS384 (default 48)</summary>
    public int HS384MinBytes { get; set; } = 48;
    /// <summary>Minimum bytes for HS512 (default 64)</summary>
    public int HS512MinBytes { get; set; } = 64;

    /// <summary>If true, enforce policy for request object (JAR) validation.</summary>
    public bool EnforceForJar { get; set; } = true;

    /// <summary>If true, enforce policy during client create/update operations.</summary>
    public bool EnforceOnClientMutation { get; set; } = true;
}
