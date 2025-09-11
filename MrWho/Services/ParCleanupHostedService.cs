using Microsoft.EntityFrameworkCore;
using MrWho.Data;

namespace MrWho.Services;

/// <summary>
/// Periodically purges expired PAR rows to keep table small. Runs every 5 minutes.
/// Writes a par.purged audit event with count when deletions occur.
/// </summary>
public sealed class ParCleanupHostedService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<ParCleanupHostedService> _logger;

    public ParCleanupHostedService(IServiceProvider services, ILogger<ParCleanupHostedService> logger)
    { _services = services; _logger = logger; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Small initial delay
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var audit = scope.ServiceProvider.GetService<ISecurityAuditWriter>();
                var cutoff = DateTime.UtcNow.AddMinutes(-2); // small grace
                var expired = await db.PushedAuthorizationRequests
                    .Where(p => p.ExpiresAt < cutoff)
                    .ToListAsync(stoppingToken);
                if (expired.Count > 0)
                {
                    db.PushedAuthorizationRequests.RemoveRange(expired);
                    await db.SaveChangesAsync(stoppingToken);
                    _logger.LogDebug("PAR cleanup removed {Count} expired rows", expired.Count);
                    if (audit != null)
                    {
                        try { await audit.WriteAsync(SecurityAudit.ParPurged, new { count = expired.Count }); } catch { }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PAR cleanup iteration failed");
            }
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}
