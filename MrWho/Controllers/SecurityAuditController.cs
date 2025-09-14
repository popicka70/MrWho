using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;

namespace MrWho.Controllers;

[ApiController]
[Route("debug/audit-chain")] // dev/debug only endpoint
[AllowAnonymous] // could restrict later; for now facilitate verification
public class SecurityAuditController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<SecurityAuditController> _logger;
    private readonly IAuditQueryService _query;

    public SecurityAuditController(ApplicationDbContext db, ILogger<SecurityAuditController> logger, IAuditQueryService query)
    { _db = db; _logger = logger; _query = query; }

    [HttpGet]
    public async Task<IActionResult> Verify([FromQuery] long? startId = null, [FromQuery] long? endId = null)
    {
        var query = _db.SecurityAuditEvents.AsNoTracking().OrderBy(e => e.Id).AsQueryable();
        if (startId.HasValue) query = query.Where(e => e.Id >= startId.Value);
        if (endId.HasValue) query = query.Where(e => e.Id <= endId.Value);
        var list = await query.ToListAsync();
        var issues = new List<object>();
        string? prevHash = null;
        foreach (var e in list)
        {
            var recomputed = ComputeHash(e, prevHash);
            if (!string.Equals(recomputed, e.Hash, StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new { e.Id, e.Category, e.EventType, Problem = "hash_mismatch", stored = e.Hash, recomputed });
            }
            if (e.PrevHash != prevHash)
            {
                // For first record, allow PrevHash null; otherwise mismatch
                if (prevHash != null)
                {
                    issues.Add(new { e.Id, e.Category, e.EventType, Problem = "prev_hash_chain_break", expectedPrev = prevHash, actualPrev = e.PrevHash });
                }
            }
            prevHash = e.Hash;
        }
        return Ok(new
        {
            count = list.Count,
            issues = issues,
            ok = issues.Count == 0,
            firstId = list.FirstOrDefault()?.Id,
            lastId = list.LastOrDefault()?.Id,
            verifiedAtUtc = DateTime.UtcNow
        });
    }

    [HttpGet("query")] // paging + filters
    public async Task<IActionResult> Query(
        [FromQuery] DateTime? fromUtc = null,
        [FromQuery] DateTime? toUtc = null,
        [FromQuery] string? category = null,
        [FromQuery] string? eventType = null,
        [FromQuery] string? actorUserId = null,
        [FromQuery] string? actorClientId = null,
        [FromQuery] string? level = null,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 100)
    {
        var (items, total) = await _query.QueryAsync(fromUtc, toUtc, category, eventType, actorUserId, actorClientId, level, page, pageSize);
        return Ok(new { page, pageSize, total, items });
    }

    [HttpGet("latest")] // quick latest fetch
    public async Task<IActionResult> Latest([FromQuery] int count = 50)
    {
        var items = await _query.GetLatestAsync(count);
        return Ok(items);
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
