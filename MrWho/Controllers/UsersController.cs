using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Handlers.Users;
using MrWho.Models;
using MrWho.Shared;
using MrWho.Shared.Models;

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
    private readonly ApplicationDbContext _context; // kept for non-parallel single operations
    private readonly IServiceScopeFactory _scopeFactory; // use scope factory instead of DbContextFactory
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
        IServiceScopeFactory scopeFactory,
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
        _scopeFactory = scopeFactory;
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

    /// <summary>
    /// Get distinct claim types used in the system
    /// </summary>
    [HttpGet("claim-types")]
    public async Task<ActionResult<List<ClaimTypeInfo>>> GetDistinctClaimTypes()
    {
        try
        {
            // Prefer canonical registry if any claim types defined
            var registered = await _context.ClaimTypes
                .Where(ct => ct.IsEnabled && !ct.IsObsolete)
                .OrderBy(ct => ct.SortOrder ?? 0)
                .ThenBy(ct => ct.DisplayName)
                .Select(ct => new ClaimTypeInfo
                {
                    Type = ct.Type,
                    DisplayName = string.IsNullOrWhiteSpace(ct.DisplayName) ? ct.Type.Replace("_", " ").ToTitleCase() : ct.DisplayName,
                    Description = ct.Description ?? (ct.IsStandard ? "Standard claim type" : "Custom claim type")
                })
                .ToListAsync();

            if (registered.Any())
            {
                return Ok(registered);
            }

            // Fallback legacy behavior
            var distinctClaimTypes = await _context.UserClaims
                .Select(c => c.ClaimType)
                .Where(ct => ct != null)
                .Distinct()
                .ToListAsync();

            var allClaimTypes = new List<ClaimTypeInfo>();
            allClaimTypes.AddRange(CommonClaimTypes.StandardClaims);
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
            return Ok(allClaimTypes.OrderBy(c => c.DisplayName).ToList());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting distinct claim types");
            return StatusCode(500, "An error occurred while retrieving claim types.");
        }
    }

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

        // Ensure deterministic ordering for paging when using Skip/Take
        query = query.OrderBy(r => r.Name);

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

        // Ensure user exists (avoid creating profile for non-existent user id)
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }

        var profile = await _context.UserProfiles.FirstOrDefaultAsync(p => p.UserId == id);
        if (profile == null)
        {
            profile = new UserProfile
            {
                UserId = id,
                DisplayName = BuildDisplayName(user.UserName ?? user.Email ?? id),
                State = newState,
                CreatedAt = DateTime.UtcNow
            };
            _context.UserProfiles.Add(profile);
        }
        else
        {
            profile.State = newState;
            profile.UpdatedAt = DateTime.UtcNow;
        }
        await _context.SaveChangesAsync();

        _logger.LogInformation("Changed/created profile state for user {UserId} to {State} by {Admin}", id, newState, User.Identity?.Name);
        return Ok(new UserProfileStateDto { State = profile.State.ToString() });
    }

    /// <summary>
    /// Get aggregated context data for editing a user (single roundtrip)
    /// Parallel version: each query uses its own DbContext instance via factory.
    /// </summary>
    [HttpGet("{id}/edit-context")]
    public async Task<ActionResult<UserEditContextDto>> GetUserEditContext(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound($"User with ID '{id}' not found.");

        var userRoleNames = await _userManager.GetRolesAsync(user);
        var userClaims = await _userManager.GetClaimsAsync(user);

        // Local helper to create an async scope and execute a query (ensures separate DbContext & good tracing)
        async Task<T> InScope<T>(Func<ApplicationDbContext, Task<T>> work)
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            return await work(db);
        }

        var profileTask = InScope(db => db.UserProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.UserId == id));

        var assignedClientsTask = InScope(db => db.ClientUsers.AsNoTracking()
            .Where(cu => cu.UserId == id)
            .Join(db.Clients.AsNoTracking(), cu => cu.ClientId, c => c.Id, (cu, c) => new { cu, c })
            .OrderBy(x => x.c.Name)
            .Select(x => new UserClientDto
            {
                ClientId = x.c.Id,
                ClientPublicId = x.c.ClientId,
                ClientName = x.c.Name,
                CreatedAt = x.cu.CreatedAt
            }).ToListAsync());

        var allClientsTask = InScope(db => db.Clients.AsNoTracking()
            .OrderBy(c => c.Name)
            .Select(c => new ClientDto
            {
                Id = c.Id,
                ClientId = c.ClientId,
                Name = c.Name,
                Description = c.Description,
                IsEnabled = c.IsEnabled,
                ClientType = c.ClientType,
                AllowAuthorizationCodeFlow = c.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = c.AllowClientCredentialsFlow,
                AllowPasswordFlow = c.AllowPasswordFlow,
                AllowRefreshTokenFlow = c.AllowRefreshTokenFlow,
                RequirePkce = c.RequirePkce,
                RequireClientSecret = c.RequireClientSecret,
                RealmId = c.RealmId,
                RealmName = c.Realm.Name,
                CreatedAt = c.CreatedAt,
                UpdatedAt = c.UpdatedAt
            }).ToListAsync());

        var globalRolesTask = InScope(db => db.Roles.AsNoTracking()
            .OrderBy(r => r.Name)
            .Select(r => new RoleDto
            {
                Id = r.Id,
                Name = r.Name!,
                Description = null,
                IsEnabled = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            }).ToListAsync());

        var clientRolesTask = InScope(db => db.ClientRoles.AsNoTracking()
            .Include(cr => cr.UserClientRoles)
            .OrderBy(cr => cr.ClientId).ThenBy(cr => cr.Name)
            .Select(cr => new ClientRoleDto
            {
                Id = cr.Id,
                Name = cr.Name,
                ClientId = cr.ClientId,
                UserCount = cr.UserClientRoles.Count
            }).ToListAsync());

        var userClientRoleAssignmentsTask = InScope(db => db.UserClientRoles.AsNoTracking()
            .Where(ucr => ucr.UserId == id)
            .Join(db.ClientRoles.AsNoTracking(), ucr => ucr.ClientRoleId, cr => cr.Id, (ucr, cr) => new { cr.ClientId, RoleName = cr.Name })
            .ToListAsync());

        await Task.WhenAll(profileTask, assignedClientsTask, allClientsTask, globalRolesTask, clientRolesTask, userClientRoleAssignmentsTask);

        var roleDtos = await globalRolesTask;
        var userRoleDtos = roleDtos.Where(r => userRoleNames.Contains(r.Name, StringComparer.OrdinalIgnoreCase)).ToList();
        var availableRoleDtos = roleDtos.Where(r => !userRoleNames.Contains(r.Name, StringComparer.OrdinalIgnoreCase)).ToList();

        var assignedClients = await assignedClientsTask;
        var allClients = await allClientsTask;
        var availableClients = allClients.Where(c => !assignedClients.Any(ac => ac.ClientId == c.Id)).ToList();

        var userClientRolesByClient = (await userClientRoleAssignmentsTask)
            .GroupBy(x => x.ClientId)
            .ToDictionary(g => g.Key, g => g.Select(x => x.RoleName).Distinct().OrderBy(n => n).ToList());

        var userWithClaims = new UserWithClaimsDto
        {
            Id = user.Id,
            UserName = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            LockoutEnabled = user.LockoutEnabled,
            LockoutEnd = user.LockoutEnd,
            AccessFailedCount = user.AccessFailedCount,
            Claims = userClaims.Select(c => new UserClaimDto { ClaimType = c.Type, ClaimValue = c.Value, Issuer = c.Issuer }).ToList(),
            Roles = userRoleNames.ToList()
        };

        return Ok(new UserEditContextDto
        {
            User = userWithClaims,
            UserRoles = userRoleDtos,
            AvailableRoles = availableRoleDtos,
            AssignedClients = assignedClients,
            AvailableClients = availableClients,
            ProfileState = await profileTask == null ? null : new UserProfileStateDto { State = (await profileTask)!.State.ToString() },
            AllClients = allClients,
            AllClientRoles = await clientRolesTask,
            UserClientRolesByClient = userClientRolesByClient
        });
    }

    private static string BuildDisplayName(string source)
    {
        if (string.IsNullOrWhiteSpace(source)) return "New User";
        if (source.Contains('@')) source = source.Split('@')[0];
        var friendly = source.Replace('.', ' ').Replace('_', ' ').Replace('-', ' ');
        var words = friendly.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return string.Join(' ', words.Select(w => char.ToUpper(w[0]) + w[1..].ToLower()));
    }
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