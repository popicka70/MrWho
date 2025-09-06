using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public class ReturnUrlStore : IReturnUrlStore
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ReturnUrlStore> _logger;

    public ReturnUrlStore(ApplicationDbContext db, ILogger<ReturnUrlStore> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task<string> SaveAsync(string url, string? clientId = null, TimeSpan? ttl = null, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var expires = now + (ttl ?? TimeSpan.FromMinutes(10));

        // Generate random, URL-safe token; retry on collision (extremely unlikely)
        string id;
        int attempts = 0;
        do
        {
            id = NewToken(20); // 160-bit token, ~27 chars base64url
            attempts++;
        } while (await _db.ReturnUrlEntries.AsNoTracking().AnyAsync(x => x.Id == id, ct) && attempts < 5);

        if (attempts >= 5)
        {
            // fallback: increase size
            id = NewToken(32);
        }

        _db.ReturnUrlEntries.Add(new ReturnUrlEntry
        {
            Id = id,
            Url = url,
            ClientId = clientId,
            CreatedAt = now,
            ExpiresAt = expires
        });
        await _db.SaveChangesAsync(ct);
        return id;
    }

    public async Task<string?> ResolveAsync(string id, CancellationToken ct = default)
    {
        var item = await _db.ReturnUrlEntries.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (item == null) return null;
        if (item.ExpiresAt <= DateTime.UtcNow) return null;
        return item.Url;
    }

    public async Task<int> CleanupExpiredAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var expired = await _db.ReturnUrlEntries.Where(x => x.ExpiresAt <= now).ToListAsync(ct);
        if (expired.Count == 0) return 0;
        _db.ReturnUrlEntries.RemoveRange(expired);
        await _db.SaveChangesAsync(ct);
        return expired.Count;
    }

    private static string NewToken(int numBytes)
    {
        Span<byte> bytes = stackalloc byte[numBytes];
        RandomNumberGenerator.Fill(bytes);
        var b64 = Convert.ToBase64String(bytes);
        return b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
