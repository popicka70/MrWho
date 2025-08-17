using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/monitoring/usage")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ApiUsageController(ApplicationDbContext context, ILogger<ApiUsageController> logger) : ControllerBase
{
    private readonly ApplicationDbContext _context = context;
    private readonly ILogger<ApiUsageController> _logger = logger;

    [HttpGet("overview")]
    public async Task<ActionResult<ApiUsageOverviewDto>> GetOverviewAsync()
    {
        var now = DateTime.UtcNow;
        var dayAgo = now.AddDays(-1);
        var weekAgo = now.AddDays(-7);

        var total = await _context.AuditLogs.LongCountAsync();
        var uniqueClients = await _context.AuditLogs
            .Where(a => a.ClientId != null)
            .Select(a => a.ClientId!)
            .Distinct()
            .CountAsync();
        var last24h = await _context.AuditLogs.LongCountAsync(a => a.OccurredAt >= dayAgo);
        var last7d = await _context.AuditLogs.LongCountAsync(a => a.OccurredAt >= weekAgo);

        return Ok(new ApiUsageOverviewDto
        {
            TotalRequests = total,
            UniqueClients = uniqueClients,
            RequestsLast24H = last24h,
            RequestsLast7D = last7d
        });
    }

    [HttpGet("top-clients")]
    public async Task<ActionResult<IEnumerable<ApiUsageTopClientDto>>> GetTopClientsAsync([FromQuery] int take = 20)
    {
        take = Math.Clamp(take, 1, 100);
        var items = await _context.AuditLogs
            .Where(a => a.ClientId != null)
            .GroupBy(a => a.ClientId!)
            .Select(g => new ApiUsageTopClientDto
            {
                ClientId = g.Key,
                Requests = g.LongCount()
            })
            .OrderByDescending(x => x.Requests)
            .Take(take)
            .ToListAsync();
        return Ok(items);
    }

    [HttpGet("top-endpoints")]
    public async Task<ActionResult<IEnumerable<ApiEndpointUsageDto>>> GetTopEndpointsAsync([FromQuery] int take = 20)
    {
        take = Math.Clamp(take, 1, 100);
        var items = await _context.AuditLogs
            .GroupBy(a => a.EntityType + ":" + a.Action)
            .Select(g => new ApiEndpointUsageDto
            {
                Endpoint = g.Key,
                Requests = g.LongCount()
            })
            .OrderByDescending(x => x.Requests)
            .Take(take)
            .ToListAsync();
        return Ok(items);
    }

    [HttpGet("timeseries")]
    public async Task<ActionResult<IEnumerable<ApiUsageTimeSeriesPointDto>>> GetTimeSeriesAsync([FromQuery] int days = 14)
    {
        days = Math.Clamp(days, 1, 90);
        var now = DateTime.UtcNow.Date;
        var start = now.AddDays(-(days - 1));

        var rows = await _context.AuditLogs
            .Where(a => a.OccurredAt >= start)
            .Select(a => a.OccurredAt.Date)
            .ToListAsync();

        var map = rows.GroupBy(d => d)
            .ToDictionary(g => g.Key, g => g.LongCount());

        var result = new List<ApiUsageTimeSeriesPointDto>(days);
        for (int i = 0; i < days; i++)
        {
            var d = start.AddDays(i);
            result.Add(new ApiUsageTimeSeriesPointDto
            {
                Date = d,
                Requests = map.TryGetValue(d, out var c) ? c : 0
            });
        }
        return Ok(result);
    }
}
