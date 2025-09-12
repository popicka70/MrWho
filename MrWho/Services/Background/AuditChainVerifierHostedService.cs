using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using System.Security.Cryptography;
using System.Text;

namespace MrWho.Services.Background;

/// <summary>
/// Periodically verifies the tail of the security audit chain for tampering.
/// Writes audit.chain_verified or audit.chain_break events.
/// </summary>
public sealed class AuditChainVerifierHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<AuditChainVerifierHostedService> _logger;

    public AuditChainVerifierHostedService(IServiceProvider services, ILogger<AuditChainVerifierHostedService> logger)
    { _services = services; _logger = logger; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial delay
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var auditWriter = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
                // Verify last N records (e.g., 500)
                const int window = 500;
                var tail = await db.SecurityAuditEvents.AsNoTracking()
                    .OrderByDescending(e => e.Id)
                    .Take(window)
                    .OrderBy(e => e.Id) // re-order ascending for chain
                    .ToListAsync(stoppingToken);
                string? prev = null;
                var issues = new List<object>();
                foreach (var e in tail)
                {
                    var recomputed = ComputeHash(e, prev);
                    if (!string.Equals(recomputed, e.Hash, StringComparison.OrdinalIgnoreCase))
                    {
                        issues.Add(new { e.Id, problem = "hash_mismatch" });
                    }
                    if (e.PrevHash != prev && prev != null)
                    {
                        issues.Add(new { e.Id, problem = "prev_hash_mismatch" });
                    }
                    prev = e.Hash;
                }
                if (auditWriter != null)
                {
                    if (issues.Count == 0)
                    {
                        try { await auditWriter.WriteAsync("audit.chain_verified", new { window, lastId = tail.LastOrDefault()?.Id }); } catch { }
                    }
                    else
                    {
                        try { await auditWriter.WriteAsync("audit.chain_break", new { window, issues }); } catch { }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Audit chain verification failed");
            }
            await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken);
        }
    }

    private static string ComputeHash(SecurityAuditEvent e, string? prevHash)
    {
        var raw = string.Join('\n', new[]
        {
            e.TimestampUtc.ToString("O"), e.Category, e.EventType, e.Level ?? "", e.ActorUserId ?? "", e.ActorClientId ?? "", e.IpAddress ?? "", e.DataJson ?? "", prevHash ?? ""
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }
}
