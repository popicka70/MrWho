using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace MrWho.Services;

public class TokenStatisticsSnapshotService : ITokenStatisticsSnapshotService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<TokenStatisticsSnapshotService> _logger;

    public TokenStatisticsSnapshotService(ApplicationDbContext context, ILogger<TokenStatisticsSnapshotService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<TokenStatisticsSnapshot> CaptureHourlyAsync(CancellationToken ct = default)
        => await CaptureAsync("hourly", ct);

    public async Task<TokenStatisticsSnapshot> CaptureDailyAsync(CancellationToken ct = default)
        => await CaptureAsync("daily", ct);

    public async Task<int> CleanupAsync(TimeSpan retainFor, CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow - retainFor;
        var old = await _context.TokenStatisticsSnapshots
            .Where(s => s.CreatedAtUtc < cutoff)
            .ToListAsync(ct);
        _context.TokenStatisticsSnapshots.RemoveRange(old);
        await _context.SaveChangesAsync(ct);
        return old.Count;
    }

    private async Task<TokenStatisticsSnapshot> CaptureAsync(string granularity, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        DateTimeOffset start;
        DateTimeOffset end;
        if (granularity == "hourly")
        {
            start = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero);
            end = start.AddHours(1);
        }
        else
        {
            start = new DateTimeOffset(now.Year, now.Month, now.Day, 0, 0, 0, TimeSpan.Zero);
            end = start.AddDays(1);
        }

        var tokens = _context.Set<OpenIddictEntityFrameworkCoreToken>();
        var accessType = OpenIddictConstants.TokenTypeHints.AccessToken.ToLowerInvariant();
        var refreshType = OpenIddictConstants.TokenTypeHints.RefreshToken.ToLowerInvariant();
        var authorizationCodeType = "authorization_code";
        var deviceCodeType = "device_code";
        var validStatus = OpenIddictConstants.Statuses.Valid.ToLowerInvariant();
        var revokedStatus = OpenIddictConstants.Statuses.Revoked.ToLowerInvariant();

        // Issued in period
        var accessIssued = await tokens.LongCountAsync(t => t.CreationDate != null && t.CreationDate >= start && t.CreationDate < end && (t.Type ?? "").ToLower() == accessType, ct);
        var refreshIssued = await tokens.LongCountAsync(t => t.CreationDate != null && t.CreationDate >= start && t.CreationDate < end && (t.Type ?? "").ToLower() == refreshType, ct);
        var authCodesIssued = await tokens.LongCountAsync(t => t.CreationDate != null && t.CreationDate >= start && t.CreationDate < end && (t.Type ?? "").ToLower() == authorizationCodeType, ct);
        var deviceCodesIssued = await tokens.LongCountAsync(t => t.CreationDate != null && t.CreationDate >= start && t.CreationDate < end && (t.Type ?? "").ToLower() == deviceCodeType, ct);

        // State at end (point-in-time)
        var activeAccessEnd = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == accessType && t.ExpirationDate != null && t.ExpirationDate > end && (t.Status == null || (t.Status ?? "").ToLower() == validStatus), ct);
        var activeRefreshEnd = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == refreshType && t.ExpirationDate != null && t.ExpirationDate > end && (t.Status == null || (t.Status ?? "").ToLower() == validStatus), ct);
        var expiredEnd = await tokens.LongCountAsync(t => t.ExpirationDate != null && t.ExpirationDate <= end, ct);
        var revokedEnd = await tokens.LongCountAsync(t => (t.Status ?? "").ToLower() == revokedStatus, ct);

        var snapshot = new TokenStatisticsSnapshot
        {
            Granularity = granularity,
            PeriodStartUtc = start,
            PeriodEndUtc = end,
            AccessTokensIssued = accessIssued,
            RefreshTokensIssued = refreshIssued,
            AuthorizationCodesIssued = authCodesIssued,
            DeviceCodesIssued = deviceCodesIssued,
            ActiveAccessTokensEnd = activeAccessEnd,
            ActiveRefreshTokensEnd = activeRefreshEnd,
            ExpiredTokensEnd = expiredEnd,
            RevokedTokensEnd = revokedEnd,
            CreatedAtUtc = DateTimeOffset.UtcNow
        };

        // Upsert by unique key (Granularity + PeriodStartUtc)
        var existing = await _context.TokenStatisticsSnapshots
            .FirstOrDefaultAsync(s => s.Granularity == granularity && s.PeriodStartUtc == start, ct);
        if (existing != null)
        {
            existing.PeriodEndUtc = snapshot.PeriodEndUtc;
            existing.AccessTokensIssued = snapshot.AccessTokensIssued;
            existing.RefreshTokensIssued = snapshot.RefreshTokensIssued;
            existing.AuthorizationCodesIssued = snapshot.AuthorizationCodesIssued;
            existing.DeviceCodesIssued = snapshot.DeviceCodesIssued;
            existing.ActiveAccessTokensEnd = snapshot.ActiveAccessTokensEnd;
            existing.ActiveRefreshTokensEnd = snapshot.ActiveRefreshTokensEnd;
            existing.ExpiredTokensEnd = snapshot.ExpiredTokensEnd;
            existing.RevokedTokensEnd = snapshot.RevokedTokensEnd;
        }
        else
        {
            _context.TokenStatisticsSnapshots.Add(snapshot);
        }

        await _context.SaveChangesAsync(ct);
        return existing ?? snapshot;
    }
}
