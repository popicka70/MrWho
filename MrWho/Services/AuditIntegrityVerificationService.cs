using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public interface IAuditIntegrityVerificationService
{
    Task<AuditIntegrityVerificationResult> VerifyAsync(int max = 0, CancellationToken ct = default);
    Task<AuditIntegrityRecord?> GetHeadAsync(CancellationToken ct = default);
}

public sealed record AuditIntegrityVerificationResult(int TotalScanned, int Breaks, string? FirstBrokenId, string? LastId, TimeSpan Elapsed);

public sealed class AuditIntegrityVerificationService : IAuditIntegrityVerificationService
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<AuditIntegrityVerificationService> _logger;

    public AuditIntegrityVerificationService(ApplicationDbContext db, ILogger<AuditIntegrityVerificationService> logger)
    { _db = db; _logger = logger; }

    public async Task<AuditIntegrityRecord?> GetHeadAsync(CancellationToken ct = default)
        => await _db.AuditIntegrityRecords.AsNoTracking().OrderByDescending(r => r.Id).FirstOrDefaultAsync(ct);

    public async Task<AuditIntegrityVerificationResult> VerifyAsync(int max = 0, CancellationToken ct = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        IQueryable<AuditIntegrityRecord> query = _db.AuditIntegrityRecords.AsNoTracking().OrderBy(r => r.Id);
        if (max > 0) {
            query = query.Take(max);
        }

        var list = await query.ToListAsync(ct);
        string? prev = null;
        string? firstBroken = null;
        int breaks = 0;
        foreach (var r in list)
        {
            var canonical = string.Join('|', new[]
            {
                r.Id,
                r.TimestampUtc.ToString("O"),
                r.Category,
                r.Action,
                r.ActorType ?? string.Empty,
                r.ActorId ?? string.Empty,
                r.SubjectType ?? string.Empty,
                r.SubjectId ?? string.Empty,
                r.RealmId ?? string.Empty,
                r.CorrelationId ?? string.Empty,
                r.DataJson ?? string.Empty
            });
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical + (prev ?? string.Empty) + r.Version.ToString())));
            if (!StringComparer.OrdinalIgnoreCase.Equals(expected, r.RecordHash))
            {
                breaks++;
                firstBroken ??= r.Id;
            }
            if (!StringComparer.OrdinalIgnoreCase.Equals(prev, r.PreviousHash) && prev != null)
            {
                breaks++;
                firstBroken ??= r.Id;
            }
            prev = r.RecordHash;
        }
        sw.Stop();
        return new AuditIntegrityVerificationResult(list.Count, breaks, firstBroken, list.LastOrDefault()?.Id, sw.Elapsed);
    }
}
