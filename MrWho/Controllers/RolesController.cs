using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class RolesController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<RolesController> _logger;

    public RolesController(
        RoleManager<IdentityRole> roleManager,
        UserManager<IdentityUser> userManager,
        ILogger<RolesController> logger)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Get all roles with pagination
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<RoleDto>>> GetRoles(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var query = _roleManager.Roles.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(r => r.Name!.Contains(search));
        }

        var totalCount = await query.CountAsync();
        var roles = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new RoleDto
            {
                Id = r.Id,
                Name = r.Name!,
                Description = null,
                IsEnabled = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                CreatedBy = null,
                UpdatedBy = null
            })
            .ToListAsync();

        var result = new PagedResult<RoleDto>
        {
            Items = roles,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        return Ok(result);
    }

    /// <summary>
    /// Get a specific role by ID
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<RoleDto>> GetRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound($"Role with ID '{id}' not found.");
        }

        var roleDto = new RoleDto
        {
            Id = role.Id,
            Name = role.Name!,
            Description = null,
            IsEnabled = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = null,
            UpdatedBy = null
        };

        return Ok(roleDto);
    }

    /// <summary>
    /// Create a new role
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<RoleDto>> CreateRole([FromBody] CreateRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var role = new IdentityRole(request.Name);
        var result = await _roleManager.CreateAsync(role);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully created role {RoleName} with ID {RoleId}", role.Name, role.Id);

        var roleDto = new RoleDto
        {
            Id = role.Id,
            Name = role.Name!,
            Description = request.Description,
            IsEnabled = request.IsEnabled,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = User.Identity?.Name,
            UpdatedBy = User.Identity?.Name
        };

        return CreatedAtAction(nameof(GetRole), new { id = role.Id }, roleDto);
    }

    /// <summary>
    /// Delete a role
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<ActionResult> DeleteRole(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound($"Role with ID '{id}' not found.");
        }

        var result = await _roleManager.DeleteAsync(role);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully deleted role {RoleName} with ID {RoleId}", role.Name, role.Id);
        return NoContent();
    }

    /// <summary>
    /// Assign role to user
    /// </summary>
    [HttpPost("assign")]
    public async Task<ActionResult> AssignRole([FromBody] AssignRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return NotFound($"User with ID '{request.UserId}' not found.");
        }

        var role = await _roleManager.FindByIdAsync(request.RoleId);
        if (role == null)
        {
            return NotFound($"Role with ID '{request.RoleId}' not found.");
        }

        if (await _userManager.IsInRoleAsync(user, role.Name!))
        {
            return BadRequest($"User '{user.UserName}' is already in role '{role.Name}'.");
        }

        var result = await _userManager.AddToRoleAsync(user, role.Name!);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully assigned role {RoleName} to user {UserName}", role.Name, user.UserName);
        return Ok($"Role '{role.Name}' assigned to user '{user.UserName}' successfully.");
    }

    /// <summary>
    /// Remove role from user
    /// </summary>
    [HttpPost("remove")]
    public async Task<ActionResult> RemoveRole([FromBody] RemoveRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return NotFound($"User with ID '{request.UserId}' not found.");
        }

        var role = await _roleManager.FindByIdAsync(request.RoleId);
        if (role == null)
        {
            return NotFound($"Role with ID '{request.RoleId}' not found.");
        }

        if (!await _userManager.IsInRoleAsync(user, role.Name!))
        {
            return BadRequest($"User '{user.UserName}' is not in role '{role.Name}'.");
        }

        var result = await _userManager.RemoveFromRoleAsync(user, role.Name!);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully removed role {RoleName} from user {UserName}", role.Name, user.UserName);
        return Ok($"Role '{role.Name}' removed from user '{user.UserName}' successfully.");
    }
}