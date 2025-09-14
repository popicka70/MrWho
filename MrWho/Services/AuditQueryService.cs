using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public sealed class AuditQueryService : IAuditQueryService
{
    private readonly ApplicationDbContext _db;
    public AuditQueryService(ApplicationDbContext db) => _db = db;

    public async Task<(IReadOnlyList<SecurityAuditEvent> Items, int Total)> QueryAsync(
        DateTime? fromUtc = null,
        DateTime? toUtc = null,
        string? category = null,
        string? eventType = null,
        string? actorUserId = null,
        string? actorClientId = null,
        string? level = null,
        int page = 1,
        int pageSize = 100,
        CancellationToken ct = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);

        var q = _db.SecurityAuditEvents.AsNoTracking();
        if (fromUtc.HasValue)
        {
            q = q.Where(e => e.TimestampUtc >= fromUtc.Value);
        }

        if (toUtc.HasValue)
        {
            q = q.Where(e => e.TimestampUtc <= toUtc.Value);
        }

        if (!string.IsNullOrWhiteSpace(category))
        {
            q = q.Where(e => e.Category == category);
        }

        if (!string.IsNullOrWhiteSpace(eventType))
        {
            q = q.Where(e => e.EventType == eventType);
        }

        if (!string.IsNullOrWhiteSpace(actorUserId))
        {
            q = q.Where(e => e.ActorUserId == actorUserId);
        }

        if (!string.IsNullOrWhiteSpace(actorClientId))
        {
            q = q.Where(e => e.ActorClientId == actorClientId);
        }

        if (!string.IsNullOrWhiteSpace(level))
        {
            q = q.Where(e => e.Level == level);
        }

        var total = await q.CountAsync(ct);
        var items = await q.OrderByDescending(e => e.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);
        return (items, total);
    }

    public async Task<IReadOnlyList<SecurityAuditEvent>> GetLatestAsync(int count = 50, CancellationToken ct = default)
    {
        count = Math.Clamp(count, 1, 500);
        return await _db.SecurityAuditEvents.AsNoTracking()
            .OrderByDescending(e => e.Id)
            .Take(count)
            .ToListAsync(ct);
    }
}
