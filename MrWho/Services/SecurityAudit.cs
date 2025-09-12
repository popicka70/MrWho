using System.Threading;
using System.Threading.Tasks;

namespace MrWho.Services;

/// <summary>
/// Helper/extension style static helpers to centralize security audit event names.
/// </summary>
public static class SecurityAudit
{
    // Categories
    public const string CategoryAuthSecurity = "auth.security";

    // MFA events
    public const string MfaEnabled = "mfa.enabled";
    public const string MfaDisabled = "mfa.disabled";
    public const string MfaVerifyFailed = "mfa.verify_failed";
    public const string MfaChallengeSuccess = "mfa.challenge_success";
    public const string MfaChallengeFailed = "mfa.challenge_failed";
    public const string MfaRecoveryCodesGenerated = "mfa.recovery_codes_generated";

    // Client secret events
    public const string ClientSecretRotated = "client_secret.rotated";
    public const string ClientSecretVerifyFailed = "client_secret.verify_failed";

    // PAR events
    public const string ParAccepted = "par.accepted";
    public const string ParRequiredMissing = "par.required_missing";
    public const string ParExpired = "par.expired";
    public const string ParConsumed = "par.consumed";
    public const string ParReuseAttempt = "par.reuse_attempt";
    public const string ParPurged = "par.purged";

    public static Task WriteAsync(this ISecurityAuditWriter writer, string eventType, object? data = null, string? level = null, string? actorUserId = null, string? actorClientId = null, string? ip = null, CancellationToken ct = default)
        => writer.WriteAsync(CategoryAuthSecurity, eventType, data, level, actorUserId, actorClientId, ip, ct);
}
