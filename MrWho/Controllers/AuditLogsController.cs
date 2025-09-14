using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class AuditLogsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AuditLogsController> _logger;

    public AuditLogsController(ApplicationDbContext context, ILogger<AuditLogsController> logger)
    {
        _context = context;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<AuditLogDto>>> GetAuditLogs(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        [FromQuery] string? search = null,
        [FromQuery] string? entityType = null,
        [FromQuery] string? action = null,
        [FromQuery] DateTime? fromUtc = null,
        [FromQuery] DateTime? toUtc = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 200) pageSize = 25;

        var query = _context.AuditLogs.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(entityType))
        {
            query = query.Where(a => a.EntityType == entityType);
        }

        if (!string.IsNullOrWhiteSpace(action))
        {
            query = query.Where(a => a.Action == action);
        }

        if (fromUtc.HasValue)
        {
            query = query.Where(a => a.OccurredAt >= fromUtc.Value);
        }

        if (toUtc.HasValue)
        {
            query = query.Where(a => a.OccurredAt <= toUtc.Value);
        }

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(a => (a.UserName != null && a.UserName.Contains(search)) ||
                                     (a.UserId != null && a.UserId.Contains(search)) ||
                                     a.EntityId.Contains(search) ||
                                     a.EntityType.Contains(search) ||
                                     (a.ClientId != null && a.ClientId.Contains(search)) ||
                                     (a.RealmId != null && a.RealmId.Contains(search)));
        }

        var totalCount = await query.CountAsync();

        var items = await query
            .OrderByDescending(a => a.OccurredAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AuditLogDto
            {
                Id = a.Id,
                OccurredAt = a.OccurredAt,
                UserId = a.UserId,
                UserName = a.UserName,
                IpAddress = a.IpAddress,
                EntityType = a.EntityType,
                EntityId = a.EntityId,
                Action = a.Action,
                Changes = a.Changes,
                RealmId = a.RealmId,
                ClientId = a.ClientId
            })
            .ToListAsync();

        return Ok(new PagedResult<AuditLogDto>
        {
            Items = items,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        });
    }

    [HttpGet("entity-types")]
    public async Task<ActionResult<IEnumerable<string>>> GetEntityTypes()
    {
        var types = await _context.AuditLogs
            .AsNoTracking()
            .Select(a => a.EntityType)
            .Distinct()
            .OrderBy(t => t)
            .ToListAsync();
        return Ok(types);
    }

    [HttpGet("actions")]
    public ActionResult<IEnumerable<string>> GetActions()
    {
        var values = Enum.GetNames(typeof(AuditAction));
        return Ok(values);
    }
}
