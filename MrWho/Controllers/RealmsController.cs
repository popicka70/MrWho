using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class RealmsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<RealmsController> _logger;

    public RealmsController(ApplicationDbContext context, ILogger<RealmsController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get all realms with pagination
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<RealmDto>>> GetRealms(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var query = _context.Realms.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(r => r.Name.Contains(search) || 
                                   (r.Description != null && r.Description.Contains(search)));
        }

        var totalCount = await query.CountAsync();
        var realms = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new RealmDto
            {
                Id = r.Id.ToString(),
                Name = r.Name,
                Description = r.Description,
                DisplayName = r.DisplayName,
                IsEnabled = r.IsEnabled,
                AccessTokenLifetime = r.AccessTokenLifetime,
                RefreshTokenLifetime = r.RefreshTokenLifetime,
                AuthorizationCodeLifetime = r.AuthorizationCodeLifetime,
                CreatedAt = r.CreatedAt,
                UpdatedAt = r.UpdatedAt,
                CreatedBy = r.CreatedBy,
                UpdatedBy = r.UpdatedBy,
                ClientCount = _context.Clients.Count(c => c.RealmId == r.Id)
            })
            .ToListAsync();

        var result = new PagedResult<RealmDto>
        {
            Items = realms,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        return Ok(result);
    }

    // ... existing code ...
}