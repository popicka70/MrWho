using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ClientRolesController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IClientRoleService _service;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<ClientRolesController> _logger;

    public ClientRolesController(ApplicationDbContext db, IClientRoleService service, UserManager<IdentityUser> userManager, ILogger<ClientRolesController> logger)
    {
        _db = db; _service = service; _userManager = userManager; _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<ClientRoleDto>>> GetRoles([FromQuery] string? clientId, [FromQuery] string? search = null)
    {
        var query = _db.ClientRoles.AsQueryable();
        if (!string.IsNullOrWhiteSpace(clientId)) query = query.Where(r => r.ClientId == clientId);
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(r => r.Name.Contains(search));
        var roles = await query
            .Select(r => new ClientRoleDto
            {
                Id = r.Id,
                Name = r.Name,
                ClientId = r.ClientId,
                UserCount = r.UserClientRoles.Count
            }).OrderBy(r => r.ClientId).ThenBy(r => r.Name).ToListAsync();
        return Ok(roles);
    }

    [HttpPost]
    public async Task<ActionResult<ClientRoleDto>> Create([FromBody] CreateClientRoleRequest request)
    {
        var client = await _db.Clients.FirstOrDefaultAsync(c => c.ClientId == request.ClientId);
        if (client == null) return NotFound("Client not found");
        var normalized = request.Name.Trim().ToUpperInvariant();
        var exists = await _db.ClientRoles.AnyAsync(r => r.ClientId == request.ClientId && r.NormalizedName == normalized);
        if (exists) return Conflict("Role already exists");
        var role = new ClientRole { ClientId = request.ClientId, Name = request.Name.Trim(), NormalizedName = normalized };
        _db.ClientRoles.Add(role);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetRoles), new { clientId = request.ClientId }, new ClientRoleDto { Id = role.Id, Name = role.Name, ClientId = role.ClientId, UserCount = 0 });
    }

    [HttpDelete]
    public async Task<IActionResult> Delete([FromBody] DeleteClientRoleRequest request)
    {
        var normalized = request.Name.Trim().ToUpperInvariant();
        var role = await _db.ClientRoles.Include(r => r.UserClientRoles).FirstOrDefaultAsync(r => r.ClientId == request.ClientId && r.NormalizedName == normalized);
        if (role == null) return NotFound();
        if (role.UserClientRoles.Count > 0) return Conflict("Role has assigned users");
        _db.ClientRoles.Remove(role);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    [HttpGet("{clientId}/users/{userId}")]
    public async Task<ActionResult<IEnumerable<string>>> GetUserClientRoles(string clientId, string userId)
    {
        var client = await _db.Clients.AnyAsync(c => c.ClientId == clientId);
        if (!client) return NotFound("Client not found");
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return NotFound("User not found");
        var roles = await _service.GetClientRolesAsync(userId, clientId);
        return Ok(roles);
    }

    [HttpPost("assign")]
    public async Task<IActionResult> Assign([FromBody] AssignClientRoleRequest request)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null) return NotFound("User not found");
        var client = await _db.Clients.AnyAsync(c => c.ClientId == request.ClientId);
        if (!client) return NotFound("Client not found");
        await _service.AddRoleToUserAsync(request.UserId, request.ClientId, request.RoleName);
        _logger.LogInformation("Assigned client role {Role} to user {UserId} for client {Client}", request.RoleName, request.UserId, request.ClientId);
        return Ok();
    }

    [HttpPost("remove")]
    public async Task<IActionResult> Remove([FromBody] RemoveClientRoleRequest request)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null) return NotFound("User not found");
        var client = await _db.Clients.AnyAsync(c => c.ClientId == request.ClientId);
        if (!client) return NotFound("Client not found");
        await _service.RemoveRoleFromUserAsync(request.UserId, request.ClientId, request.RoleName);
        _logger.LogInformation("Removed client role {Role} from user {UserId} for client {Client}", request.RoleName, request.UserId, request.ClientId);
        return Ok();
    }

    [HttpGet("{clientId}/roles/{roleName}/users")]
    public async Task<ActionResult<IEnumerable<object>>> GetUsersForRole(string clientId, string roleName)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(roleName)) return BadRequest();
        var normalized = roleName.Trim().ToUpperInvariant();
        var role = await _db.ClientRoles.FirstOrDefaultAsync(r => r.ClientId == clientId && r.NormalizedName == normalized);
        if (role == null) return NotFound("Role not found");
        var users = await _db.UserClientRoles
            .Where(ucr => ucr.ClientRoleId == role.Id)
            .Join(_db.Users, ucr => ucr.UserId, u => u.Id, (ucr, u) => new { u.Id, u.UserName, u.Email })
            .OrderBy(u => u.UserName)
            .ToListAsync();
        return Ok(users);
    }
}
