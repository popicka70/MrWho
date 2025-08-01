using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;

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
                                   (r.DisplayName != null && r.DisplayName.Contains(search)) ||
                                   (r.Description != null && r.Description.Contains(search)));
        }

        var totalCount = await query.CountAsync();
        var realms = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new RealmDto
            {
                Id = r.Id,
                Name = r.Name,
                Description = r.Description,
                IsEnabled = r.IsEnabled,
                DisplayName = r.DisplayName,
                AccessTokenLifetime = r.AccessTokenLifetime,
                RefreshTokenLifetime = r.RefreshTokenLifetime,
                AuthorizationCodeLifetime = r.AuthorizationCodeLifetime,
                CreatedAt = r.CreatedAt,
                UpdatedAt = r.UpdatedAt,
                CreatedBy = r.CreatedBy,
                UpdatedBy = r.UpdatedBy,
                ClientCount = r.Clients.Count
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

    [HttpGet("{id}")]
    public async Task<ActionResult<RealmDto>> GetRealm(string id)
    {
        var realm = await _context.Realms
            .Include(r => r.Clients)
            .FirstOrDefaultAsync(r => r.Id == id);

        if (realm == null)
        {
            return NotFound($"Realm with ID '{id}' not found.");
        }

        var realmDto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            IsEnabled = realm.IsEnabled,
            DisplayName = realm.DisplayName,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = realm.Clients.Count
        };

        return Ok(realmDto);
    }

    [HttpPost]
    public async Task<ActionResult<RealmDto>> CreateRealm([FromBody] CreateRealmRequest request)
    {
        if (await _context.Realms.AnyAsync(r => r.Name == request.Name))
        {
            return BadRequest($"Realm with name '{request.Name}' already exists.");
        }

        var realm = new Realm
        {
            Name = request.Name,
            Description = request.Description,
            DisplayName = request.DisplayName,
            IsEnabled = request.IsEnabled,
            AccessTokenLifetime = request.AccessTokenLifetime,
            RefreshTokenLifetime = request.RefreshTokenLifetime,
            AuthorizationCodeLifetime = request.AuthorizationCodeLifetime,
            CreatedBy = User.Identity?.Name
        };

        _context.Realms.Add(realm);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Realm '{RealmName}' created successfully with ID {RealmId}", realm.Name, realm.Id);

        var realmDto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            IsEnabled = realm.IsEnabled,
            DisplayName = realm.DisplayName,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = 0
        };

        return CreatedAtAction(nameof(GetRealm), new { id = realm.Id }, realmDto);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<RealmDto>> UpdateRealm(string id, [FromBody] CreateRealmRequest request)
    {
        var realm = await _context.Realms.FindAsync(id);
        if (realm == null)
        {
            return NotFound($"Realm with ID '{id}' not found.");
        }

        if (realm.Name != request.Name && await _context.Realms.AnyAsync(r => r.Name == request.Name))
        {
            return BadRequest($"Realm with name '{request.Name}' already exists.");
        }

        realm.Name = request.Name;
        realm.Description = request.Description;
        realm.DisplayName = request.DisplayName;
        realm.IsEnabled = request.IsEnabled;
        realm.AccessTokenLifetime = request.AccessTokenLifetime;
        realm.RefreshTokenLifetime = request.RefreshTokenLifetime;
        realm.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime;
        realm.UpdatedAt = DateTime.UtcNow;
        realm.UpdatedBy = User.Identity?.Name;

        await _context.SaveChangesAsync();

        _logger.LogInformation("Realm '{RealmName}' updated successfully", realm.Name);

        var realmDto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            IsEnabled = realm.IsEnabled,
            DisplayName = realm.DisplayName,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(realmDto);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRealm(string id)
    {
        var realm = await _context.Realms
            .Include(r => r.Clients)
            .FirstOrDefaultAsync(r => r.Id == id);

        if (realm == null)
        {
            return NotFound($"Realm with ID '{id}' not found.");
        }

        if (realm.Clients.Any())
        {
            return BadRequest($"Cannot delete realm '{realm.Name}' because it has {realm.Clients.Count} associated clients. Delete the clients first.");
        }

        _context.Realms.Remove(realm);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Realm '{RealmName}' deleted successfully", realm.Name);

        return NoContent();
    }

    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<RealmDto>> ToggleRealm(string id)
    {
        var realm = await _context.Realms.FindAsync(id);
        if (realm == null)
        {
            return NotFound($"Realm with ID '{id}' not found.");
        }

        realm.IsEnabled = !realm.IsEnabled;
        realm.UpdatedAt = DateTime.UtcNow;
        realm.UpdatedBy = User.Identity?.Name;

        await _context.SaveChangesAsync();

        var action = realm.IsEnabled ? "enabled" : "disabled";
        _logger.LogInformation("Realm '{RealmName}' {Action} successfully", realm.Name, action);

        var realmDto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            IsEnabled = realm.IsEnabled,
            DisplayName = realm.DisplayName,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(realmDto);
    }
}