using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Shared;
using MrWho.Shared.Models;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using MrWho.Models;
using MrWho.Services;

namespace MrWho.Controllers;

[ApiController]
[Route("api/monitoring/tokens")] 
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class TokenStatisticsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<TokenStatisticsController> _logger;
    private readonly ITokenStatisticsSnapshotService _snapshotService;

    public TokenStatisticsController(ApplicationDbContext context, ILogger<TokenStatisticsController> logger, ITokenStatisticsSnapshotService snapshotService)
    {
        _context = context;
        _logger = logger;
        _snapshotService = snapshotService;
    }

    [HttpGet("overview")]
    public async Task<ActionResult<TokenStatisticsOverviewDto>> GetOverviewAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var tokens = _context.Set<OpenIddictEntityFrameworkCoreToken>();

        var accessType = OpenIddictConstants.TokenTypeHints.AccessToken.ToLowerInvariant();
        var refreshType = OpenIddictConstants.TokenTypeHints.RefreshToken.ToLowerInvariant();
        var authorizationCodeType = "authorization_code";
        var deviceCodeType = "device_code";

        var validStatus = OpenIddictConstants.Statuses.Valid.ToLowerInvariant();
        var revokedStatus = OpenIddictConstants.Statuses.Revoked.ToLowerInvariant();
        var redeemedStatus = OpenIddictConstants.Statuses.Redeemed.ToLowerInvariant();

        var total = await tokens.LongCountAsync();
        var access = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == accessType);
        var refresh = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == refreshType);
        var authCodes = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == authorizationCodeType);
        var deviceCodes = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == deviceCodeType);

        var activeAccess = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == accessType
            && t.ExpirationDate != null && t.ExpirationDate > now
            && (t.Status == null || (t.Status ?? "").ToLower() == validStatus));

        var activeRefresh = await tokens.LongCountAsync(t => (t.Type ?? "").ToLower() == refreshType
            && t.ExpirationDate != null && t.ExpirationDate > now
            && (t.Status == null || (t.Status ?? "").ToLower() == validStatus));

        var expired = await tokens.LongCountAsync(t => t.ExpirationDate != null && t.ExpirationDate <= now);
        var revoked = await tokens.LongCountAsync(t => (t.Status ?? "").ToLower() == revokedStatus);
        var redeemed = await tokens.LongCountAsync(t => (t.Status ?? "").ToLower() == redeemedStatus || t.RedemptionDate != null);

        var dayAgo = now.AddDays(-1);
        var weekAgo = now.AddDays(-7);
        var last24h = await tokens.LongCountAsync(t => t.CreationDate != null && t.CreationDate >= dayAgo);
        var last7d = await tokens.LongCountAsync(t => t.CreationDate != null && t.CreationDate >= weekAgo);

        var dto = new TokenStatisticsOverviewDto
        {
            TotalTokens = total,
            AccessTokens = access,
            RefreshTokens = refresh,
            AuthorizationCodes = authCodes,
            DeviceCodes = deviceCodes,
            ActiveAccessTokens = activeAccess,
            ActiveRefreshTokens = activeRefresh,
            ExpiredTokens = expired,
            RevokedTokens = revoked,
            RedeemedTokens = redeemed,
            IssuedLast24H = last24h,
            IssuedLast7D = last7d
        };

        return Ok(dto);
    }

    [HttpGet("top-clients")]
    public async Task<ActionResult<IEnumerable<TokenClientStatDto>>> GetTopClientsAsync([FromQuery] int take = 20)
    {
        take = Math.Clamp(take, 1, 100);

        var now = DateTimeOffset.UtcNow;
        var tokens = _context.Set<OpenIddictEntityFrameworkCoreToken>()
            .Include(t => t.Application)
            .Include(t => t.Authorization)!
                .ThenInclude(a => a!.Application);

        var accessType = OpenIddictConstants.TokenTypeHints.AccessToken.ToLowerInvariant();
        var refreshType = OpenIddictConstants.TokenTypeHints.RefreshToken.ToLowerInvariant();
        var validStatus = OpenIddictConstants.Statuses.Valid.ToLowerInvariant();
        var revokedStatus = OpenIddictConstants.Statuses.Revoked.ToLowerInvariant();

        // Materialize minimal fields to aggregate in-memory (keeps translation simple across providers)
        var rows = await tokens.Select(t => new
        {
            ClientId = t.Application != null ? t.Application.ClientId : (t.Authorization != null && t.Authorization.Application != null ? t.Authorization.Application.ClientId : null),
            ClientName = t.Application != null ? t.Application.DisplayName : (t.Authorization != null && t.Authorization.Application != null ? t.Authorization.Application.DisplayName : null),
            Type = (t.Type ?? "").ToLower(),
            Exp = t.ExpirationDate,
            Status = (t.Status ?? "").ToLower()
        }).ToListAsync();

        var groups = rows
            .GroupBy(r => new { ClientId = r.ClientId ?? "<no-client>", r.ClientName })
            .Select(g => new TokenClientStatDto
            {
                ClientId = g.Key.ClientId,
                ClientName = g.Key.ClientName,
                AccessTokens = g.LongCount(r => r.Type == accessType),
                RefreshTokens = g.LongCount(r => r.Type == refreshType),
                ActiveAccessTokens = g.LongCount(r => r.Type == accessType && r.Exp != null && r.Exp > now && (string.IsNullOrEmpty(r.Status) || r.Status == validStatus)),
                ActiveRefreshTokens = g.LongCount(r => r.Type == refreshType && r.Exp != null && r.Exp > now && (string.IsNullOrEmpty(r.Status) || r.Status == validStatus)),
                RevokedTokens = g.LongCount(r => r.Status == revokedStatus)
            })
            .OrderByDescending(x => x.AccessTokens + x.RefreshTokens)
            .ThenByDescending(x => x.ActiveAccessTokens + x.ActiveRefreshTokens)
            .Take(take)
            .ToList();

        return Ok(groups);
    }

    [HttpGet("timeseries")]
    public async Task<ActionResult<IEnumerable<TokenTimeSeriesPointDto>>> GetTimeSeriesAsync([FromQuery] int days = 14)
    {
        days = Math.Clamp(days, 1, 90);
        var now = DateTimeOffset.UtcNow;
        var start = new DateTimeOffset(now.Date.AddDays(-(days - 1)), TimeSpan.Zero);

        var tokens = _context.Set<OpenIddictEntityFrameworkCoreToken>();

        var accessType = OpenIddictConstants.TokenTypeHints.AccessToken.ToLowerInvariant();
        var refreshType = OpenIddictConstants.TokenTypeHints.RefreshToken.ToLowerInvariant();
        var authorizationCodeType = "authorization_code";
        var deviceCodeType = "device_code";

        // Load minimal projections and aggregate in-memory by day
        var rows = await tokens
            .Where(t => t.CreationDate != null && t.CreationDate >= start)
            .Select(t => new { Date = t.CreationDate!.Value.Date, Type = (t.Type ?? string.Empty).ToLower() })
            .ToListAsync();

        var byDay = rows
            .GroupBy(r => DateOnly.FromDateTime(r.Date))
            .ToDictionary(g => g.Key, g => new
            {
                Access = g.LongCount(r => r.Type == accessType),
                Refresh = g.LongCount(r => r.Type == refreshType),
                Auth = g.LongCount(r => r.Type == authorizationCodeType),
                Device = g.LongCount(r => r.Type == deviceCodeType)
            });

        var points = new List<TokenTimeSeriesPointDto>(days);
        for (var i = 0; i < days; i++)
        {
            var d = DateOnly.FromDateTime(start.AddDays(i).Date);
            if (byDay.TryGetValue(d, out var agg))
            {
                points.Add(new TokenTimeSeriesPointDto
                {
                    Date = d,
                    AccessTokens = agg.Access,
                    RefreshTokens = agg.Refresh,
                    AuthorizationCodes = agg.Auth,
                    DeviceCodes = agg.Device
                });
            }
            else
            {
                points.Add(new TokenTimeSeriesPointDto { Date = d });
            }
        }

        return Ok(points);
    }

    // === Snapshot persistence endpoints ===

    [HttpPost("snapshots/capture/hourly")]
    public async Task<ActionResult<TokenStatisticsSnapshot>> CaptureHourlyAsync(CancellationToken ct)
        => Ok(await _snapshotService.CaptureHourlyAsync(ct));

    [HttpPost("snapshots/capture/daily")]
    public async Task<ActionResult<TokenStatisticsSnapshot>> CaptureDailyAsync(CancellationToken ct)
        => Ok(await _snapshotService.CaptureDailyAsync(ct));

    [HttpPost("snapshots/cleanup")]
    public async Task<ActionResult<int>> CleanupAsync([FromQuery] int retainDays = 90, CancellationToken ct = default)
    {
        retainDays = Math.Clamp(retainDays, 7, 3650);
        var removed = await _snapshotService.CleanupAsync(TimeSpan.FromDays(retainDays), ct);
        return Ok(removed);
    }

    [HttpGet("snapshots")]
    public async Task<ActionResult<IEnumerable<TokenStatisticsSnapshot>>> GetSnapshotsAsync([FromQuery] string granularity = "daily", [FromQuery] int take = 60)
    {
        take = Math.Clamp(take, 1, 1000);
        var items = await _context.TokenStatisticsSnapshots
            .Where(s => s.Granularity == granularity)
            .OrderByDescending(s => s.PeriodStartUtc)
            .Take(take)
            .ToListAsync();
        return Ok(items);
    }
}
