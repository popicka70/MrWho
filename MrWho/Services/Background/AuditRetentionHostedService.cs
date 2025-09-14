using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;

namespace MrWho.Services.Background;

/// <summary>
/// Periodically prunes old security audit events based on retention policy.
/// Keeps at least MinEventsToKeep newest events regardless of age.
/// </summary>
public sealed class AuditRetentionHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<AuditRetentionHostedService> _logger;
    private readonly IOptions<AuditRetentionOptions> _options;

    public AuditRetentionHostedService(IServiceProvider services, ILogger<AuditRetentionHostedService> logger, IOptions<AuditRetentionOptions> options)
    { _services = services; _logger = logger; _options = options; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken); // initial delay
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunOnceAsync(stoppingToken); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _logger.LogWarning(ex, "Audit retention pass failed"); }
            await Task.Delay(TimeSpan.FromHours(6), stoppingToken); // twice daily
        }
    }

    private async Task RunOnceAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var auditWriter = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
        var opts = _options.Value;
        var cutoff = DateTime.UtcNow.AddDays(-opts.KeepDays);

        // Count total
        var total = await db.SecurityAuditEvents.CountAsync(ct);
        if (total <= opts.MinEventsToKeep)
        {
            _logger.LogDebug("Audit retention skipped; total {Total} <= MinEventsToKeep {Min}", total, opts.MinEventsToKeep);
            return;
        }

        // Determine max deletable keeping MinEventsToKeep newest
        var newestIdsToKeep = await db.SecurityAuditEvents
            .OrderByDescending(e => e.Id)
            .Skip(opts.MinEventsToKeep)
            .Select(e => e.Id)
            .ToListAsync(ct); // IDs older than the kept set

        if (newestIdsToKeep.Count == 0) {
            return; // nothing extra beyond floor
        }

        var maxIdToDelete = newestIdsToKeep.Max();

        var batch = opts.BatchSize;
        var deletable = await db.SecurityAuditEvents
            .Where(e => e.TimestampUtc < cutoff && e.Id <= maxIdToDelete)
            .OrderBy(e => e.Id)
            .Take(batch)
            .ToListAsync(ct);
        if (deletable.Count == 0)
        {
            _logger.LogDebug("Audit retention found no deletable events (cutoff {Cutoff:O})", cutoff);
            return;
        }

        db.SecurityAuditEvents.RemoveRange(deletable);
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("Audit retention removed {Count} events older than {Cutoff:O}", deletable.Count, cutoff);
        if (auditWriter != null)
        {
            try { await auditWriter.WriteAsync("audit.retention_pruned", new { removed = deletable.Count, cutoff }); } catch { }
        }
    }
}
