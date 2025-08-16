using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using Microsoft.AspNetCore.RateLimiting; // added

namespace MrWho.Controllers;

[ApiController]
[Route("api/register")]
[AllowAnonymous]
public class PublicRegistrationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<PublicRegistrationController> _logger;

    public PublicRegistrationController(UserManager<IdentityUser> userManager, ApplicationDbContext db, ILogger<PublicRegistrationController> logger)
    {
        _userManager = userManager;
        _db = db;
        _logger = logger;
    }

    [HttpPost]
    [EnableRateLimiting("rl.register")] // rate limit public registrations per IP
    public async Task<ActionResult<RegisterUserResponse>> Register([FromBody] RegisterUserRequest input)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new RegisterUserResponse { Success = false, Error = "Invalid registration data." });
        }

        var existingByEmail = await _userManager.FindByEmailAsync(input.Email);
        if (existingByEmail != null)
        {
            return Conflict(new RegisterUserResponse { Success = false, Error = "An account with this email already exists." });
        }

        var user = new IdentityUser
        {
            UserName = input.Email,
            Email = input.Email,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user, input.Password);
        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            _logger.LogWarning("Registration failed for {Email}: {Error}", input.Email, error);
            return BadRequest(new RegisterUserResponse { Success = false, Error = error });
        }

        var profile = new UserProfile
        {
            UserId = user.Id,
            FirstName = input.FirstName,
            LastName = input.LastName,
            DisplayName = $"{input.FirstName} {input.LastName}".Trim(),
            State = UserState.New,
            CreatedAt = DateTime.UtcNow
        };
        _db.UserProfiles.Add(profile);
        await _db.SaveChangesAsync();

        _logger.LogInformation("Registration submitted for {Email} (UserId={UserId})", input.Email, user.Id);
        return Ok(new RegisterUserResponse { Success = true, UserId = user.Id });
    }
}
