using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared; // added
using MrWho.Shared.Models;

namespace MrWho.Controllers;

[ApiController]
[Route("api/registrations")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)]
public class RegistrationsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<RegistrationsController> _logger;

    public RegistrationsController(ApplicationDbContext context, UserManager<IdentityUser> userManager, ILogger<RegistrationsController> logger)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    // GET: api/registrations/pending
    [HttpGet("pending")]
    public async Task<ActionResult<List<PendingUserDto>>> GetPending()
    {
        var query = from u in _context.Users
                    join p in _context.UserProfiles on u.Id equals p.UserId into up
                    from p in up.DefaultIfEmpty()
                    where p != null && p.State == UserState.New
                    orderby p!.CreatedAt descending
                    select new PendingUserDto
                    {
                        Id = u.Id,
                        UserName = u.UserName ?? string.Empty,
                        Email = u.Email ?? string.Empty,
                        FirstName = p!.FirstName,
                        LastName = p!.LastName,
                        DisplayName = p!.DisplayName,
                        State = p!.State.ToString(),
                        CreatedAt = p!.CreatedAt
                    };

        var items = await query.ToListAsync();
        return Ok(items);
    }

    // POST: api/registrations/{id}/approve
    [HttpPost("{id}/approve")]
    public async Task<IActionResult> Approve(string id)
    {
        var profile = await _context.UserProfiles.FirstOrDefaultAsync(p => p.UserId == id);
        if (profile == null) {
            return NotFound("User profile not found");
        }

        profile.State = UserState.Active;
        profile.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        _logger.LogInformation("Approved user {UserId}", id);
        return Ok();
    }

    // POST: api/registrations/{id}/reject
    [HttpPost("{id}/reject")]
    public async Task<IActionResult> Reject(string id)
    {
        var profile = await _context.UserProfiles.FirstOrDefaultAsync(p => p.UserId == id);
        if (profile == null) {
            return NotFound("User profile not found");
        }

        profile.State = UserState.Disabled;
        profile.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        _logger.LogInformation("Rejected user {UserId}", id);
        return Ok();
    }
}
