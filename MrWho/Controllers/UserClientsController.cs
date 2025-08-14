using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/users/{userId}/clients")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class UserClientsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<UserClientsController> _logger;

    public UserClientsController(ApplicationDbContext context, UserManager<IdentityUser> userManager, ILogger<UserClientsController> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<UserClientsListDto>> GetUserClients(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            // Allow lookup by username/email as convenience
            user = await _userManager.FindByNameAsync(userId) ?? await _userManager.FindByEmailAsync(userId);
        }
        if (user == null) return NotFound($"User '{userId}' not found");

        var assignments = await _context.ClientUsers
            .Where(cu => cu.UserId == user.Id)
            .Join(_context.Clients, cu => cu.ClientId, c => c.Id, (cu, c) => new { cu, c })
            .OrderBy(x => x.c.Name)
            .ToListAsync();

        var dto = new UserClientsListDto
        {
            UserId = user.Id,
            UserName = user.UserName ?? string.Empty,
            UserEmail = user.Email,
            Clients = assignments.Select(x => new UserClientDto
            {
                ClientId = x.c.Id,
                ClientPublicId = x.c.ClientId,
                ClientName = x.c.Name,
                CreatedAt = x.cu.CreatedAt
            }).ToList()
        };

        return Ok(dto);
    }
}
