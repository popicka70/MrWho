using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared; // Added for AuthorizationPolicies
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ClaimTypesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ClaimTypesController> _logger;

    public ClaimTypesController(ApplicationDbContext context, ILogger<ClaimTypesController> logger)
    {
        _context = context;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<ClaimTypeInfo>>> GetClaimTypes()
    {
        var result = await _context.ClaimTypes
            .AsNoTracking()
            .OrderBy(ct => ct.SortOrder ?? 0).ThenBy(ct => ct.DisplayName)
            .Select(ct => new ClaimTypeInfo
            {
                Type = ct.Type,
                DisplayName = ct.DisplayName,
                Description = ct.Description ?? string.Empty
            })
            .ToListAsync();
        return Ok(result);
    }

    [HttpGet("{type}")]
    public async Task<ActionResult<ClaimTypeInfo>> GetClaimType(string type)
    {
        var ct = await _context.ClaimTypes.AsNoTracking().FirstOrDefaultAsync(c => c.Type == type);
        if (ct == null) return NotFound();
        return Ok(new ClaimTypeInfo(ct.Type, ct.DisplayName, ct.Description ?? string.Empty));
    }

    public record UpsertClaimTypeRequest(string Type, string DisplayName, string? Description, string? Category, bool IsEnabled, bool IsObsolete, int? SortOrder);

    [HttpPost]
    public async Task<ActionResult<ClaimTypeInfo>> Create([FromBody] UpsertClaimTypeRequest request)
    {
        if (await _context.ClaimTypes.AnyAsync(c => c.Type == request.Type))
        {
            return Conflict($"Claim type '{request.Type}' already exists");
        }
        var entity = new ClaimType
        {
            Type = request.Type,
            DisplayName = request.DisplayName,
            Description = request.Description,
            Category = request.Category,
            IsEnabled = request.IsEnabled,
            IsObsolete = request.IsObsolete,
            SortOrder = request.SortOrder,
            CreatedBy = User.Identity?.Name
        };
        _context.ClaimTypes.Add(entity);
        await _context.SaveChangesAsync();
        return CreatedAtAction(nameof(GetClaimType), new { type = entity.Type }, new ClaimTypeInfo(entity.Type, entity.DisplayName, entity.Description ?? string.Empty));
    }

    [HttpPut("{type}")]
    public async Task<ActionResult<ClaimTypeInfo>> Update(string type, [FromBody] UpsertClaimTypeRequest request)
    {
        var entity = await _context.ClaimTypes.FirstOrDefaultAsync(c => c.Type == type);
        if (entity == null) return NotFound();
        entity.DisplayName = request.DisplayName;
        entity.Description = request.Description;
        entity.Category = request.Category;
        entity.IsEnabled = request.IsEnabled;
        entity.IsObsolete = request.IsObsolete;
        entity.SortOrder = request.SortOrder;
        entity.UpdatedAt = DateTime.UtcNow;
        entity.UpdatedBy = User.Identity?.Name;
        await _context.SaveChangesAsync();
        return Ok(new ClaimTypeInfo(entity.Type, entity.DisplayName, entity.Description ?? string.Empty));
    }

    [HttpDelete("{type}")]
    public async Task<IActionResult> Delete(string type)
    {
        var entity = await _context.ClaimTypes.FirstOrDefaultAsync(c => c.Type == type);
        if (entity == null) return NotFound();
        _context.ClaimTypes.Remove(entity);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}
