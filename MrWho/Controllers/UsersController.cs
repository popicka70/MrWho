using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Models;
using MrWho.Handlers.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Shared.Models;
using MrWho.Shared;
using System.Security.Claims;
using System.Globalization;
using MrWho.Data;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class UsersController : ControllerBase
{
    private readonly IGetUsersHandler _getUsersHandler;
    private readonly IGetUserHandler _getUserHandler;
    private readonly ICreateUserHandler _createUserHandler;
    private readonly IUpdateUserHandler _updateUserHandler;
    private readonly IDeleteUserHandler _deleteUserHandler;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        IGetUsersHandler getUsersHandler,
        IGetUserHandler getUserHandler,
        ICreateUserHandler createUserHandler,
        IUpdateUserHandler updateUserHandler,
        IDeleteUserHandler deleteUserHandler,
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ApplicationDbContext context,
        ILogger<UsersController> logger)
    {
        _getUsersHandler = getUsersHandler;
        _getUserHandler = getUserHandler;
        _createUserHandler = createUserHandler;
        _updateUserHandler = updateUserHandler;
        _deleteUserHandler = deleteUserHandler;
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get all users with pagination
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<UserDto>>> GetUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        var result = await _getUsersHandler.HandleAsync(page, pageSize, search);
        return Ok(result);
    }

    /// <summary>
    /// Get a specific user by ID
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<UserDto>> GetUser(string id)
    {
        var user = await _getUserHandler.HandleAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }
        return Ok(user);
    }

    /// <summary>
    /// Get a specific user with claims and roles
    /// </summary>
    [HttpGet("{id}/with-claims")]
    public async Task<ActionResult<UserWithClaimsDto>> GetUserWithClaims(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        var claims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        var userWithClaims = new UserWithClaimsDto
        {
            Id = user.Id,
            UserName = user.UserName!,
            Email = user.Email!,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            LockoutEnabled = user.LockoutEnabled,
            LockoutEnd = user.LockoutEnd,
            AccessFailedCount = user.AccessFailedCount,
            Claims = claims.Select(c => new UserClaimDto
            {
                ClaimType = c.Type,
                ClaimValue = c.Value,
                Issuer = c.Issuer
            }).ToList(),
            Roles = roles.ToList()
        };

        return Ok(userWithClaims);
    }

    /// <summary>
    /// Create a new user
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<UserDto>> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, user, errors) = await _createUserHandler.HandleAsync(request);

        if (!success)
        {
            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User {UserName} created successfully with ID {UserId}", user!.UserName, user.Id);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }

    /// <summary>
    /// Update an existing user
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<UserDto>> UpdateUser(string id, [FromBody] UpdateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, user, errors) = await _updateUserHandler.HandleAsync(id, request);

        if (!success)
        {
            if (user == null)
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User {UserName} updated successfully", user!.UserName);
        return Ok(user);
    }

    /// <summary>
    /// Delete a user
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var (success, errors) = await _deleteUserHandler.HandleAsync(id);

        if (!success)
        {
            var errorsList = errors.ToList();
            if (errorsList.Any(e => e.Contains("not found")))
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errorsList)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User with ID {UserId} deleted successfully", id);
        return NoContent();
    }

    #region User Claims Management

    /// <summary>
    /// Get all claims for a specific user
    /// </summary>
    [HttpGet("{id}/claims")]
    public async Task<ActionResult<List<UserClaimDto>>> GetUserClaims(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        var claims = await _userManager.GetClaimsAsync(user);
        var claimDtos = claims.Select(c => new UserClaimDto
        {
            ClaimType = c.Type,
            ClaimValue = c.Value,
            Issuer = c.Issuer
        }).ToList();

        return Ok(claimDtos);
    }

    /// <summary>
    /// Add a claim to a user
    /// </summary>
    [HttpPost("{id}/claims")]
    public async Task<ActionResult> AddUserClaim(string id, [FromBody] AddUserClaimRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        // Check if claim already exists
        var existingClaims = await _userManager.GetClaimsAsync(user);
        if (existingClaims.Any(c => c.Type == request.ClaimType && c.Value == request.ClaimValue))
        {
            return BadRequest($"User already has claim '{request.ClaimType}' with value '{request.ClaimValue}'.");
        }

        var claim = new Claim(request.ClaimType, request.ClaimValue);
        var result = await _userManager.AddClaimAsync(user, claim);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully added claim '{ClaimType}' with value '{ClaimValue}' to user {UserName}", 
            request.ClaimType, request.ClaimValue, user.UserName);

        return Ok($"Claim '{request.ClaimType}' added to user '{user.UserName}' successfully.");
    }

    /// <summary>
    /// Remove a claim from a user
    /// </summary>
    [HttpDelete("{id}/claims")]
    public async Task<ActionResult> RemoveUserClaim(string id, [FromBody] RemoveUserClaimRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        // Check if claim exists
        var existingClaims = await _userManager.GetClaimsAsync(user);
        var claimToRemove = existingClaims.FirstOrDefault(c => c.Type == request.ClaimType && c.Value == request.ClaimValue);
        
        if (claimToRemove == null)
        {
            return NotFound($"User does not have claim '{request.ClaimType}' with value '{request.ClaimValue}'.");
        }

        var result = await _userManager.RemoveClaimAsync(user, claimToRemove);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully removed claim '{ClaimType}' with value '{ClaimValue}' from user {UserName}", 
            request.ClaimType, request.ClaimValue, user.UserName);

        return Ok($"Claim '{request.ClaimType}' removed from user '{user.UserName}' successfully.");
    }

    /// <summary>
    /// Update a claim for a user
    /// </summary>
    [HttpPut("{id}/claims")]
    public async Task<ActionResult> UpdateUserClaim(string id, [FromBody] UpdateUserClaimRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        // Check if old claim exists
        var existingClaims = await _userManager.GetClaimsAsync(user);
        var oldClaim = existingClaims.FirstOrDefault(c => c.Type == request.OldClaimType && c.Value == request.OldClaimValue);
        
        if (oldClaim == null)
        {
            return NotFound($"User does not have claim '{request.OldClaimType}' with value '{request.OldClaimValue}'.");
        }

        // Check if new claim already exists (unless it's the same claim)
        if (!(request.OldClaimType == request.NewClaimType && request.OldClaimValue == request.NewClaimValue))
        {
            if (existingClaims.Any(c => c.Type == request.NewClaimType && c.Value == request.NewClaimValue))
            {
                return BadRequest($"User already has claim '{request.NewClaimType}' with value '{request.NewClaimValue}'.");
            }
        }

        var newClaim = new Claim(request.NewClaimType, request.NewClaimValue);
        var result = await _userManager.ReplaceClaimAsync(user, oldClaim, newClaim);

        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Successfully updated claim for user {UserName} from '{OldType}:{OldValue}' to '{NewType}:{NewValue}'", 
            user.UserName, request.OldClaimType, request.OldClaimValue, request.NewClaimType, request.NewClaimValue);

        return Ok($"Claim updated successfully for user '{user.UserName}'.");
    }

    #endregion

    #region Claim Types Management

    /// <summary>
    /// Get distinct claim types used in the system
    /// </summary>
    [HttpGet("claim-types")]
    public async Task<ActionResult<List<ClaimTypeInfo>>> GetDistinctClaimTypes()
    {
        try
        {
            // Get distinct claim types from AspNetUserClaims table directly
            var distinctClaimTypes = await _context.UserClaims
                .Select(c => c.ClaimType)
                .Where(ct => ct != null)
                .Distinct()
                .ToListAsync();

            // Combine standard claims with custom claims from database
            var allClaimTypes = new List<ClaimTypeInfo>();
            
            // Add all standard claims
            allClaimTypes.AddRange(CommonClaimTypes.StandardClaims);
            
            // Add custom claims that aren't already in the standard list
            foreach (var claimType in distinctClaimTypes)
            {
                if (!string.IsNullOrEmpty(claimType) && !allClaimTypes.Any(c => c.Type == claimType))
                {
                    allClaimTypes.Add(new ClaimTypeInfo(
                        claimType, 
                        claimType.Replace("_", " ").ToTitleCase(), 
                        "Custom claim type from database"
                    ));
                }
            }

            // Sort by display name for better UX
            return Ok(allClaimTypes.OrderBy(c => c.DisplayName).ToList());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting distinct claim types");
            return StatusCode(500, "An error occurred while retrieving claim types.");
        }
    }

    #endregion

    #region Roles Management

    /// <summary>
    /// Get roles for a specific user
    /// </summary>
    [HttpGet("{id}/roles")]
    public async Task<ActionResult<List<RoleDto>>> GetUserRoles(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        var userRoles = await _userManager.GetRolesAsync(user);
        var roles = new List<RoleDto>();

        foreach (var roleName in userRoles)
        {
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role != null)
            {
                roles.Add(new RoleDto
                {
                    Id = role.Id,
                    Name = role.Name!,
                    Description = null,
                    IsEnabled = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow,
                    CreatedBy = null,
                    UpdatedBy = null
                });
            }
        }

        return Ok(roles);
    }

    /// <summary>
    /// Assign role to user
    /// </summary>
    [HttpPost("{id}/roles")]
    public async Task<ActionResult> AssignUserRole(string id, [FromBody] AssignRoleRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
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
    [HttpDelete("{id}/roles/{roleId}")]
    public async Task<ActionResult> RemoveUserRole(string id, string roleId)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null)
        {
            return NotFound($"Role with ID '{roleId}' not found.");
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

    #endregion

    #region Roles Management

    /// <summary>
    /// Get all roles with pagination
    /// </summary>
    [HttpGet("roles")]
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
    /// Create a new role
    /// </summary>
    [HttpPost("roles")]
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

        return Ok(roleDto);
    }

    #endregion

    #region Profile State Management

    /// <summary>
    /// Get the UserProfile.State for the specified user
    /// </summary>
    [HttpGet("{id}/profile-state")]
    public async Task<ActionResult<UserProfileStateDto>> GetProfileState(string id)
    {
        var profile = await _context.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == id);
        if (profile == null)
        {
            return NotFound("User profile not found");
        }

        return Ok(new UserProfileStateDto { State = profile.State.ToString() });
    }

    /// <summary>
    /// Set the UserProfile.State for the specified user
    /// </summary>
    [HttpPost("{id}/profile-state")]
    public async Task<ActionResult> SetProfileState(string id, [FromBody] SetUserProfileStateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.State))
        {
            return BadRequest("State is required");
        }

        if (!Enum.TryParse<UserState>(request.State, ignoreCase: true, out var newState))
        {
            return BadRequest($"Invalid state '{request.State}'. Allowed: {string.Join(", ", Enum.GetNames(typeof(UserState)))}");
        }

        var profile = await _context.UserProfiles.FirstOrDefaultAsync(p => p.UserId == id);
        if (profile == null)
        {
            return NotFound("User profile not found");
        }

        profile.State = newState;
        profile.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        _logger.LogInformation("Changed profile state for user {UserId} to {State} by {Admin}", id, newState, User.Identity?.Name);
        return Ok(new UserProfileStateDto { State = profile.State.ToString() });
    }

    #endregion
}

/// <summary>
/// Request model for updating user claims
/// </summary>
public class UpdateUserClaimRequest
{
    public string OldClaimType { get; set; } = string.Empty;
    public string OldClaimValue { get; set; } = string.Empty;
    public string NewClaimType { get; set; } = string.Empty;
    public string NewClaimValue { get; set; } = string.Empty;
}

/// <summary>
/// Extension methods for string manipulation
/// </summary>
public static class StringExtensions
{
    public static string ToTitleCase(this string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        return CultureInfo.CurrentCulture.TextInfo.ToTitleCase(input.ToLower());
    }
}