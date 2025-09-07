using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Services;

public sealed class ConsentService : IConsentService
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ConsentService> _logger;

    public ConsentService(ApplicationDbContext db, ILogger<ConsentService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task<Consent?> GetAsync(string userId, string clientId, CancellationToken ct = default)
    {
        return await _db.Consents.AsNoTracking().FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId, ct);
    }

    public async Task<Consent> GrantAsync(string userId, string clientId, IEnumerable<string> grantedScopes, CancellationToken ct = default)
    {
        var scopes = NormalizeScopes(grantedScopes);
        var existing = await _db.Consents.FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId, ct);
        var now = DateTime.UtcNow;
        if (existing == null)
        {
            existing = new Consent
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ClientId = clientId,
                CreatedAt = now,
                UpdatedAt = now
            };
            existing.SetGrantedScopes(scopes);
            _db.Consents.Add(existing);
        }
        else
        {
            existing.SetGrantedScopes(scopes);
            existing.UpdatedAt = now;
        }

        await _db.SaveChangesAsync(ct);
        return existing;
    }

    public async Task ForgetAsync(string userId, string clientId, CancellationToken ct = default)
    {
        var existing = await _db.Consents.FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId, ct);
        if (existing != null)
        {
            _db.Consents.Remove(existing);
            await _db.SaveChangesAsync(ct);
        }
    }

    public IReadOnlyList<string> DiffMissingScopes(IEnumerable<string> requested, IEnumerable<string> alreadyGranted)
    {
        var req = NormalizeScopes(requested).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var granted = NormalizeScopes(alreadyGranted).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Consent is required for any requested scope that is not yet in granted.
        return req.Where(s => !granted.Contains(s)).OrderBy(s => s).ToArray();
    }

    private static IEnumerable<string> NormalizeScopes(IEnumerable<string> scopes)
        => scopes.Where(s => !string.IsNullOrWhiteSpace(s))
                 .Select(s => s.Trim())
                 .Distinct(StringComparer.OrdinalIgnoreCase)
                 .OrderBy(s => s);
}
