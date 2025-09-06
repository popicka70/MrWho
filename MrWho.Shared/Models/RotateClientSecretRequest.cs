namespace MrWho.Shared.Models;

public class RotateClientSecretRequest
{
    /// <summary>
    /// Optional caller-provided new secret. If null, server will generate a random high-entropy secret.
    /// </summary>
    public string? NewSecret { get; set; }

    /// <summary>
    /// Optional expiration timestamp for the new secret (UTC). If null, secret does not expire automatically.
    /// </summary>
    public DateTime? ExpiresAtUtc { get; set; }

    /// <summary>
    /// Whether to mark existing active secrets as retired immediately.
    /// Default true.
    /// </summary>
    public bool? RetireOld { get; set; } = true;
}
