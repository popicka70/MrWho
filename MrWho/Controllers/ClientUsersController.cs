using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/clients/{clientId}/users")] // clientId accepts either DB id or public ClientId
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class ClientUsersController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<ClientUsersController> _logger;

    public ClientUsersController(ApplicationDbContext context, UserManager<IdentityUser> userManager, ILogger<ClientUsersController> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    private async Task<Client?> FindClientByIdOrPublicIdAsync(string clientId)
    {
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == clientId);
        if (client != null) {
            return client;
        }

        return await _context.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId);
    }

    [HttpGet]
    public async Task<ActionResult<ClientUsersListDto>> GetAssignedUsers(string clientId)
    {
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == clientId || c.ClientId == clientId);
        if (client == null) {
            return NotFound($"Client '{clientId}' not found");
        }

        var assignments = await _context.ClientUsers
            .Where(cu => cu.ClientId == client.Id)
            .Join(_context.Users, cu => cu.UserId, u => u.Id, (cu, u) => new { cu, u })
            .OrderBy(x => x.u.UserName)
            .ToListAsync();

        var dto = new ClientUsersListDto
        {
            ClientId = client.Id,
            ClientPublicId = client.ClientId,
            ClientName = client.Name,
            Users = assignments.Select(x => new ClientUserDto
            {
                Id = x.cu.Id,
                ClientId = x.cu.ClientId,
                ClientPublicId = client.ClientId,
                ClientName = client.Name,
                UserId = x.u.Id,
                UserName = x.u.UserName ?? string.Empty,
                UserEmail = x.u.Email,
                CreatedAt = x.cu.CreatedAt
            }).ToList()
        };

        return Ok(dto);
    }

    [HttpPost]
    public async Task<ActionResult<ClientUserDto>> AssignUser(string clientId, [FromBody] AssignClientUserRequest request)
    {
        var client = await FindClientByIdOrPublicIdAsync(clientId);
        if (client == null) {
            return NotFound($"Client '{clientId}' not found");
        }

        var user = await _userManager.FindByIdAsync(request.UserId) ?? await _userManager.FindByNameAsync(request.UserId);
        if (user == null) {
            return NotFound($"User '{request.UserId}' not found");
        }

        var exists = await _context.ClientUsers.AnyAsync(cu => cu.ClientId == client.Id && cu.UserId == user.Id);
        if (exists)
        {
            return Conflict("User already assigned to this client");
        }

        var assignment = new ClientUser
        {
            ClientId = client.Id,
            UserId = user.Id,
            CreatedAt = DateTime.UtcNow,
            CreatedBy = User?.Identity?.Name
        };
        _context.ClientUsers.Add(assignment);
        await _context.SaveChangesAsync();

        var dto = new ClientUserDto
        {
            Id = assignment.Id,
            ClientId = assignment.ClientId,
            ClientPublicId = client.ClientId,
            ClientName = client.Name,
            UserId = user.Id,
            UserName = user.UserName ?? string.Empty,
            UserEmail = user.Email,
            CreatedAt = assignment.CreatedAt
        };

        return CreatedAtAction(nameof(GetAssignedUsers), new { clientId = client.Id }, dto);
    }

    [HttpDelete("{userId}")]
    public async Task<IActionResult> RemoveUser(string clientId, string userId)
    {
        var client = await FindClientByIdOrPublicIdAsync(clientId);
        if (client == null) {
            return NotFound($"Client '{clientId}' not found");
        }

        var assignment = await _context.ClientUsers.FirstOrDefaultAsync(cu => cu.ClientId == client.Id && cu.UserId == userId);
        if (assignment == null) {
            return NotFound("Assignment not found");
        }

        _context.ClientUsers.Remove(assignment);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}
