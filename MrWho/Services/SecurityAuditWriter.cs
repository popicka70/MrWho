using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public sealed class SecurityAuditWriter : ISecurityAuditWriter
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<SecurityAuditWriter> _logger;
    private readonly IAuditIntegrityWriter _integrityWriter; // NEW
    private readonly ICorrelationContextAccessor _correlation;

    public SecurityAuditWriter(ApplicationDbContext db, ILogger<SecurityAuditWriter> logger, IAuditIntegrityWriter integrityWriter, ICorrelationContextAccessor correlation)
    {
        _db = db;
        _logger = logger;
        _integrityWriter = integrityWriter;
        _correlation = correlation;
    }

    public async Task<SecurityAuditEvent> WriteAsync(string category, string eventType, object? data = null,
        string? level = null, string? actorUserId = null, string? actorClientId = null, string? ip = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(category))
        {
            category = "general";
        }

        if (string.IsNullOrWhiteSpace(eventType))
        {
            eventType = "unknown";
        }

        var correlationId = _correlation.Current.CorrelationId;
        var resolvedActorUserId = actorUserId ?? _correlation.Current.ActorUserId;
        var resolvedActorClientId = actorClientId ?? _correlation.Current.ActorClientId;

        var last = await _db.SecurityAuditEvents
            .AsNoTracking()
            .OrderByDescending(e => e.Id)
            .Select(e => new { e.Id, e.Hash })
            .FirstOrDefaultAsync(ct);

        string? prevHash = last?.Hash;
        var timestamp = DateTime.UtcNow;
        string? dataJson = null;
        if (data != null)
        {
            try { dataJson = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = false }); }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to serialize audit data for {EventType}", eventType); }
        }

        string material = string.Join('|', new[]
        {
            timestamp.ToString("O"),
            category,
            eventType,
            level ?? string.Empty,
            resolvedActorUserId ?? string.Empty,
            resolvedActorClientId ?? string.Empty,
            ip ?? string.Empty,
            dataJson ?? string.Empty,
            prevHash ?? string.Empty
        });
        var hash = ComputeHash(material);

        var entry = new SecurityAuditEvent
        {
            TimestampUtc = timestamp,
            Category = category,
            EventType = eventType,
            Level = level,
            ActorUserId = resolvedActorUserId,
            ActorClientId = resolvedActorClientId,
            IpAddress = ip,
            DataJson = dataJson,
            PrevHash = prevHash,
            Hash = hash
        };

        _db.SecurityAuditEvents.Add(entry);
        await _db.SaveChangesAsync(ct);
        _logger.LogDebug("Audit event persisted: {Category}/{Type} id={Id} corr={CorrelationId}", category, eventType, entry.Id, correlationId);

        // ALSO write integrity chain record (maps event -> action) including correlation id
        try
        {
            var actorType = resolvedActorUserId != null ? "user" : resolvedActorClientId != null ? "client" : "system";
            await _integrityWriter.WriteAsync(new AuditIntegrityWriteRequest(
                Category: category,
                Action: eventType,
                ActorType: actorType,
                ActorId: resolvedActorUserId ?? resolvedActorClientId,
                SubjectType: null,
                SubjectId: null,
                RealmId: null,
                CorrelationId: correlationId,
                Data: data,
                Version: 1
            ), ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to append audit integrity record for {Category}/{Type}", category, eventType);
        }

        return entry;
    }

    private static string ComputeHash(string material)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(material)));
    }
}
