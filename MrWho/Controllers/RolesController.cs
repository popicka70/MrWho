using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Shared.Models;
using System.Security.Claims;

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
            .ToListAsync();

        var roleDtos = new List<RoleDto>();
        foreach (var role in roles)
        {
            var claims = await _roleManager.GetClaimsAsync(role);
            var description = claims.FirstOrDefault(c => c.Type == "description")?.Value;
            var isEnabledClaim = claims.FirstOrDefault(c => c.Type == "enabled")?.Value;
            var isEnabled = string.IsNullOrEmpty(isEnabledClaim) || bool.Parse(isEnabledClaim);

            roleDtos.Add(new RoleDto
            {
                Id = role.Id,
                Name = role.Name!,
                Description = description,
                IsEnabled = isEnabled,
                CreatedAt = DateTime.UtcNow, // IdentityRole doesn't have timestamps
                UpdatedAt = DateTime.UtcNow,
                CreatedBy = null,
                UpdatedBy = null
            });
        }

        var result = new PagedResult<RoleDto>
        {
            Items = roleDtos,
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

        var claims = await _roleManager.GetClaimsAsync(role);
        var description = claims.FirstOrDefault(c => c.Type == "description")?.Value;
        var isEnabledClaim = claims.FirstOrDefault(c => c.Type == "enabled")?.Value;
        var isEnabled = string.IsNullOrEmpty(isEnabledClaim) || bool.Parse(isEnabledClaim);

        var roleDto = new RoleDto
        {
            Id = role.Id,
            Name = role.Name!,
            Description = description,
            IsEnabled = isEnabled,
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

        // Add description as a role claim if provided
        if (!string.IsNullOrEmpty(request.Description))
        {
            await _roleManager.AddClaimAsync(role, new Claim("description", request.Description));
        }

        // Add enabled status as a role claim
        await _roleManager.AddClaimAsync(role, new Claim("enabled", request.IsEnabled.ToString()));

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
    /// Update an existing role
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<RoleDto>> UpdateRole(string id, [FromBody] UpdateRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound($"Role with ID '{id}' not found.");
        }

        // Update role name if provided
        if (!string.IsNullOrEmpty(request.Name) && request.Name != role.Name)
        {
            role.Name = request.Name;
            var updateResult = await _roleManager.UpdateAsync(role);
            if (!updateResult.Succeeded)
            {
                foreach (var error in updateResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return BadRequest(ModelState);
            }
        }

        // Update description claim
        if (request.Description != null)
        {
            var claims = await _roleManager.GetClaimsAsync(role);
            var existingDescriptionClaim = claims.FirstOrDefault(c => c.Type == "description");
            
            if (existingDescriptionClaim != null)
            {
                await _roleManager.RemoveClaimAsync(role, existingDescriptionClaim);
            }
            
            if (!string.IsNullOrEmpty(request.Description))
            {
                await _roleManager.AddClaimAsync(role, new Claim("description", request.Description));
            }
        }

        // Update enabled status claim
        if (request.IsEnabled.HasValue)
        {
            var claims = await _roleManager.GetClaimsAsync(role);
            var existingEnabledClaim = claims.FirstOrDefault(c => c.Type == "enabled");
            
            if (existingEnabledClaim != null)
            {
                await _roleManager.RemoveClaimAsync(role, existingEnabledClaim);
            }
            
            await _roleManager.AddClaimAsync(role, new Claim("enabled", request.IsEnabled.Value.ToString()));
        }

        _logger.LogInformation("Successfully updated role {RoleName} with ID {RoleId}", role.Name, role.Id);

        // Get updated claims for response
        var updatedClaims = await _roleManager.GetClaimsAsync(role);
        var description = updatedClaims.FirstOrDefault(c => c.Type == "description")?.Value;
        var isEnabledClaim = updatedClaims.FirstOrDefault(c => c.Type == "enabled")?.Value;
        var isEnabled = string.IsNullOrEmpty(isEnabledClaim) || bool.Parse(isEnabledClaim);

        var roleDto = new RoleDto
        {
            Id = role.Id,
            Name = role.Name!,
            Description = description,
            IsEnabled = isEnabled,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = null,
            UpdatedBy = User.Identity?.Name
        };

        return Ok(roleDto);
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

        // Prevent deletion of critical system roles
        var protectedRoles = new[] { "Administrator", "User" };
        if (protectedRoles.Contains(role.Name))
        {
            return BadRequest($"The '{role.Name}' role is protected and cannot be deleted as it's required for system operation.");
        }

        // Check if role is assigned to any users
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
        if (usersInRole.Any())
        {
            return BadRequest($"Cannot delete role '{role.Name}' because it is assigned to {usersInRole.Count} user(s). Remove the role from all users first.");
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

    /// <summary>
    /// Get users assigned to a specific role
    /// </summary>
    [HttpGet("{id}/users")]
    public async Task<ActionResult<PagedResult<UserDto>>> GetRoleUsers(
        string id,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 10;

        var role = await _roleManager.FindByIdAsync(id);
        if (role == null)
        {
            return NotFound($"Role with ID '{id}' not found.");
        }

        // Get all users in the role
        var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
        
        // Apply search filter if provided
        IEnumerable<IdentityUser> filteredUsers = usersInRole;
        if (!string.IsNullOrWhiteSpace(search))
        {
            filteredUsers = usersInRole.Where(u => 
                (u.UserName != null && u.UserName.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
                (u.Email != null && u.Email.Contains(search, StringComparison.OrdinalIgnoreCase)));
        }

        var totalCount = filteredUsers.Count();
        var pagedUsers = filteredUsers
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserDto
            {
                Id = u.Id,
                UserName = u.UserName!,
                Email = u.Email!,
                EmailConfirmed = u.EmailConfirmed,
                PhoneNumber = u.PhoneNumber,
                PhoneNumberConfirmed = u.PhoneNumberConfirmed,
                TwoFactorEnabled = u.TwoFactorEnabled,
                LockoutEnabled = u.LockoutEnabled,
                LockoutEnd = u.LockoutEnd,
                AccessFailedCount = u.AccessFailedCount
            })
            .ToList();

        var result = new PagedResult<UserDto>
        {
            Items = pagedUsers,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };

        _logger.LogInformation("Retrieved {UserCount} users for role '{RoleName}' (page {Page})", 
            pagedUsers.Count, role.Name, page);

        return Ok(result);
    }
}