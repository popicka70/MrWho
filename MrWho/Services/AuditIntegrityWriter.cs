using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

/// <summary>
/// Writes append-only chained audit integrity records.
/// </summary>
public sealed class AuditIntegrityWriter : IAuditIntegrityWriter
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<AuditIntegrityWriter> _logger;
    private readonly ICorrelationContextAccessor _correlation;
    private readonly IIntegrityHashService _hashService;
    private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = false };

    public AuditIntegrityWriter(ApplicationDbContext db, ILogger<AuditIntegrityWriter> logger, ICorrelationContextAccessor correlation, IIntegrityHashService hashService)
    { _db = db; _logger = logger; _correlation = correlation; _hashService = hashService; }

    public async Task<AuditIntegrityRecord> WriteAsync(AuditIntegrityWriteRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Category)) throw new ArgumentException("Category required", nameof(request));
        if (string.IsNullOrWhiteSpace(request.Action)) throw new ArgumentException("Action required", nameof(request));

        // Get last record hash
        var prev = await _db.AuditIntegrityRecords.AsNoTracking()
            .OrderByDescending(r => r.Id)
            .Select(r => new { r.Id, r.RecordHash })
            .FirstOrDefaultAsync(ct);

        string? dataJson = null;
        if (request.Data != null)
        {
            try { dataJson = JsonSerializer.Serialize(request.Data, _jsonOptions); }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to serialize audit integrity data"); }
        }

        var correlationId = request.CorrelationId ?? _correlation.Current.CorrelationId;

        var record = new AuditIntegrityRecord
        {
            Category = request.Category,
            Action = request.Action,
            ActorType = request.ActorType ?? _correlation.Current.ActorType,
            ActorId = request.ActorId ?? _correlation.Current.ActorUserId ?? _correlation.Current.ActorClientId,
            SubjectType = request.SubjectType,
            SubjectId = request.SubjectId,
            RealmId = request.RealmId,
            CorrelationId = correlationId,
            DataJson = dataJson,
            PreviousHash = prev?.RecordHash,
            Version = request.Version,
            TimestampUtc = DateTime.UtcNow
        };

        // Compute canonical representation (exclude RecordHash)
        var canonical = BuildCanonical(record);
        record.RecordHash = _hashService.ComputeChainHash(canonical, record.PreviousHash, record.Version);

        _db.AuditIntegrityRecords.Add(record);
        await _db.SaveChangesAsync(ct);
        return record;
    }

    private static string BuildCanonical(AuditIntegrityRecord r)
    {
        // Canonical: pipe-delimited ordered fields
        return string.Join('|', new[]
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
    }
}
