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
