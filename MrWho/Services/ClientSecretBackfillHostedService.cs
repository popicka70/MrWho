using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared; // for ClientType enum

namespace MrWho.Services;

/// <summary>
/// One-time backfill that migrates legacy plaintext client secrets stored in Clients table
/// into the ClientSecretHistories table and replaces the plaintext with the redaction marker "{HASHED}".
/// Safe to run multiple times; it only processes clients that still have plaintext.
/// </summary>
public sealed class ClientSecretBackfillHostedService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ClientSecretBackfillHostedService> _logger;

    public ClientSecretBackfillHostedService(IServiceScopeFactory scopeFactory, ILogger<ClientSecretBackfillHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var secretService = scope.ServiceProvider.GetRequiredService<IClientSecretService>();

            // Find legacy clients with plaintext secrets (not the redaction marker)
            var candidates = await db.Clients
                .Where(c => c.ClientSecret != null && c.ClientSecret != "{HASHED}" &&
                            (c.ClientType == ClientType.Confidential || c.ClientType == ClientType.Machine) &&
                            c.RequireClientSecret)
                .Select(c => new { c.Id, c.ClientId, c.ClientSecret })
                .ToListAsync(stoppingToken);

            if (candidates.Count == 0)
            {
                _logger.LogInformation("ClientSecretBackfill: no plaintext secrets to migrate");
                return;
            }

            _logger.LogInformation("ClientSecretBackfill: migrating {Count} client secrets", candidates.Count);

            foreach (var c in candidates)
            {
                try
                {
                    await secretService.SetNewSecretAsync(c.Id, providedPlaintext: c.ClientSecret, markOldAsRetired: true, ct: stoppingToken);
                    _logger.LogInformation("ClientSecretBackfill: migrated client {ClientId}", c.ClientId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "ClientSecretBackfill: failed to migrate client {ClientId}", c.ClientId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ClientSecretBackfill: fatal error");
        }
    }
}
