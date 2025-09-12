using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public sealed class ClientSecretService : IClientSecretService
{
    private readonly ApplicationDbContext _db;
    private readonly IClientSecretHasher _hasher;
    private readonly ILogger<ClientSecretService> _logger;
    private readonly ISecurityAuditWriter _audit;

    public ClientSecretService(ApplicationDbContext db, IClientSecretHasher hasher, ILogger<ClientSecretService> logger, ISecurityAuditWriter audit)
    {
        _db = db;
        _hasher = hasher;
        _logger = logger;
        _audit = audit;
    }

    public async Task<(ClientSecretHistory record, string? plainSecret)> SetNewSecretAsync(string clientId, string? providedPlaintext = null, DateTime? expiresAt = null, bool markOldAsRetired = true, CancellationToken ct = default)
    {
        var client = await _db.Clients.FirstOrDefaultAsync(c => c.Id == clientId || c.ClientId == clientId, ct);
        if (client is null) throw new InvalidOperationException($"Client '{clientId}' not found");

        // Optionally retire previous active secrets
        if (markOldAsRetired)
        {
            var actives = await _db.Set<ClientSecretHistory>()
                .Where(s => s.ClientId == client.Id && s.Status == ClientSecretStatus.Active)
                .ToListAsync(ct);
            foreach (var a in actives)
            {
                a.Status = ClientSecretStatus.Retired;
                a.ExpiresAt ??= DateTime.UtcNow; // immediate retirement
            }
        }

        var plain = providedPlaintext ?? GenerateHighEntropySecret();
        var hash = _hasher.HashSecret(plain);

        var rec = new ClientSecretHistory
        {
            ClientId = client.Id,
            SecretHash = hash,
            Algo = hash.StartsWith("PBKDF2", StringComparison.OrdinalIgnoreCase) ? "PBKDF2" : "Unknown",
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            Status = ClientSecretStatus.Active,
            IsCompromised = false
        };
        _db.Add(rec);

        // Store a redaction marker in Client.ClientSecret to avoid breaking existing flows that expect a value
        client.ClientSecret = "{HASHED}";
        await _db.SaveChangesAsync(ct);

        // Audit - do not include plaintext or hash
        try
        {
            _db.AuditLogs.Add(new AuditLog
            {
                OccurredAt = DateTime.UtcNow,
                UserId = null,
                UserName = null,
                IpAddress = null,
                EntityType = nameof(Client),
                EntityId = client.Id,
                Action = "SecretRotated",
                Changes = System.Text.Json.JsonSerializer.Serialize(new { NewSecretCreatedAtUtc = rec.CreatedAt, ExpiresAtUtc = rec.ExpiresAt, Algorithm = rec.Algo })
            });
            await _db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write audit for secret rotation of client {ClientId}", client.ClientId);
        }

        _logger.LogInformation("Created new secret for client {ClientId}", client.ClientId);
        try { await _audit.WriteAsync(SecurityAudit.ClientSecretRotated, new { clientId = client.ClientId, recordId = rec.Id, rec.CreatedAt, rec.ExpiresAt, algo = rec.Algo }, "info", actorClientId: client.ClientId, ct: ct); } catch { }
        return (rec, providedPlaintext == null ? plain : null);
    }

    public async Task<bool> VerifyAsync(string clientPublicIdOrDbId, string presentedSecret, CancellationToken ct = default)
    {
        var client = await _db.Clients.FirstOrDefaultAsync(c => c.Id == clientPublicIdOrDbId || c.ClientId == clientPublicIdOrDbId, ct);
        if (client is null) return false;

        var secrets = await _db.Set<ClientSecretHistory>()
            .Where(s => s.ClientId == client.Id && s.Status == ClientSecretStatus.Active && (!s.ExpiresAt.HasValue || s.ExpiresAt > DateTime.UtcNow))
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(ct);

        foreach (var s in secrets)
        {
            if (_hasher.Verify(presentedSecret, s.SecretHash))
            {
                s.LastUsedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync(ct);
                return true;
            }
        }
        try { await _audit.WriteAsync(SecurityAudit.ClientSecretVerifyFailed, new { clientId = client.ClientId }, "warn", actorClientId: client.ClientId, ct: ct); } catch { }
        return false;
    }

    private static string GenerateHighEntropySecret()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(48);
        return Convert.ToBase64String(bytes).Replace('+','-').Replace('/','_').TrimEnd('=');
    }
}
