using MrWho.Models;

namespace MrWho.Services;

public interface IAuditQueryService
{
    Task<(IReadOnlyList<SecurityAuditEvent> Items, int Total)> QueryAsync(
        DateTime? fromUtc = null,
        DateTime? toUtc = null,
        string? category = null,
        string? eventType = null,
        string? actorUserId = null,
        string? actorClientId = null,
        string? level = null,
        int page = 1,
        int pageSize = 100,
        CancellationToken ct = default);

    Task<IReadOnlyList<SecurityAuditEvent>> GetLatestAsync(int count = 50, CancellationToken ct = default);
}
