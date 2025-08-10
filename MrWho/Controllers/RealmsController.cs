using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Shared;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
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

    /// <summary>
    /// Get a single realm by id
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<RealmDto>> GetRealmById(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(dto);
    }

    /// <summary>
    /// Create a new realm
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<RealmDto>> CreateRealm([FromBody] CreateRealmRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        // Ensure unique name
        var exists = await _context.Realms.AnyAsync(r => r.Name == request.Name);
        if (exists)
        {
            ModelState.AddModelError(nameof(request.Name), "A realm with this name already exists.");
            return ValidationProblem(ModelState);
        }

        var now = DateTime.UtcNow;
        var userName = User?.Identity?.Name;

        var realm = new Realm
        {
            Name = request.Name,
            DisplayName = request.DisplayName,
            Description = request.Description,
            IsEnabled = request.IsEnabled,
            AccessTokenLifetime = request.AccessTokenLifetime,
            RefreshTokenLifetime = request.RefreshTokenLifetime,
            AuthorizationCodeLifetime = request.AuthorizationCodeLifetime,
            // Keep IdTokenLifetime and DeviceCodeLifetime defaults from model
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = userName,
            UpdatedBy = userName
        };

        _context.Realms.Add(realm);
        await _context.SaveChangesAsync();

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = 0
        };

        return CreatedAtAction(nameof(GetRealmById), new { id = realm.Id }, dto);
    }

    /// <summary>
    /// Update an existing realm
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<RealmDto>> UpdateRealm(string id, [FromBody] CreateRealmRequest request)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        // Name is considered immutable by UI, but if provided different, keep original
        realm.DisplayName = request.DisplayName;
        realm.Description = request.Description;
        realm.IsEnabled = request.IsEnabled;
        realm.AccessTokenLifetime = request.AccessTokenLifetime;
        realm.RefreshTokenLifetime = request.RefreshTokenLifetime;
        realm.AuthorizationCodeLifetime = request.AuthorizationCodeLifetime;
        realm.UpdatedAt = DateTime.UtcNow;
        realm.UpdatedBy = User?.Identity?.Name;

        await _context.SaveChangesAsync();

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(dto);
    }

    /// <summary>
    /// Delete a realm
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        // Optionally, prevent deletion if clients exist
        var clientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id);
        if (clientCount > 0)
        {
            return Conflict(new { message = "Cannot delete a realm that has clients." });
        }

        _context.Realms.Remove(realm);
        await _context.SaveChangesAsync();
        return NoContent();
    }

    /// <summary>
    /// Toggle realm enabled/disabled
    /// </summary>
    [HttpPost("{id}/toggle")]
    public async Task<ActionResult<RealmDto>> ToggleRealm(string id)
    {
        var realm = await _context.Realms.FirstOrDefaultAsync(r => r.Id == id);
        if (realm == null)
        {
            return NotFound();
        }

        realm.IsEnabled = !realm.IsEnabled;
        realm.UpdatedAt = DateTime.UtcNow;
        realm.UpdatedBy = User?.Identity?.Name;
        await _context.SaveChangesAsync();

        var dto = new RealmDto
        {
            Id = realm.Id,
            Name = realm.Name,
            Description = realm.Description,
            DisplayName = realm.DisplayName,
            IsEnabled = realm.IsEnabled,
            AccessTokenLifetime = realm.AccessTokenLifetime,
            RefreshTokenLifetime = realm.RefreshTokenLifetime,
            AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
            IdTokenLifetime = realm.IdTokenLifetime,
            DeviceCodeLifetime = realm.DeviceCodeLifetime,
            CreatedAt = realm.CreatedAt,
            UpdatedAt = realm.UpdatedAt,
            CreatedBy = realm.CreatedBy,
            UpdatedBy = realm.UpdatedBy,
            ClientCount = await _context.Clients.CountAsync(c => c.RealmId == realm.Id)
        };

        return Ok(dto);
    }
}