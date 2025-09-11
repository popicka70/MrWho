using MrWho.Models;

namespace MrWho.Services;

public interface ISecurityAuditWriter
{
    Task<SecurityAuditEvent> WriteAsync(string category, string eventType, object? data = null,
        string? level = null, string? actorUserId = null, string? actorClientId = null, string? ip = null,
        CancellationToken ct = default);
}
