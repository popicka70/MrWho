using MrWho.Models;

namespace MrWho.Services;

public interface ISecurityAuditWriter
{
    Task<SecurityAuditEvent> WriteAsync(string category, string eventType, object? data = null,
        string? level = null, string? actorUserId = null, string? actorClientId = null, string? ip = null,
        CancellationToken ct = default);
}

public interface IAuditIntegrityWriter
{
    Task<AuditIntegrityRecord> WriteAsync(AuditIntegrityWriteRequest request, CancellationToken ct = default);
}

public sealed record AuditIntegrityWriteRequest(
    string Category,
    string Action,
    string? ActorType = null,
    string? ActorId = null,
    string? SubjectType = null,
    string? SubjectId = null,
    string? RealmId = null,
    string? CorrelationId = null,
    object? Data = null,
    int Version = 1
);

public interface IIntegrityHashService
{
    /// <summary>
    /// Compute a deterministic hash for the audit integrity record.
    /// </summary>
    /// <param name="canonical">Canonical ordered representation excluding RecordHash.</param>
    /// <param name="previousHash">Previous record hash in the chain (may be null/empty for first record).</param>
    /// <param name="version">Schema/hash algorithm version integer.</param>
    /// <returns>Hex (uppercase) SHA-256 hash string.</returns>
    string ComputeChainHash(string canonical, string? previousHash, int version);
}
