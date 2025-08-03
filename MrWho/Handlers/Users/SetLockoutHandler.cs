using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public class SetLockoutHandler : ISetLockoutHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<SetLockoutHandler> _logger;

    public SetLockoutHandler(UserManager<IdentityUser> userManager, ILogger<SetLockoutHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<(bool Success, string Action, IEnumerable<string> Errors)> HandleAsync(string id, SetLockoutRequest request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return (false, "", new[] { "User not found" });
            }

            string action;
            IdentityResult result;

            if (request.LockoutEnd.HasValue && request.LockoutEnd > DateTimeOffset.UtcNow)
            {
                // Lock the user
                result = await _userManager.SetLockoutEndDateAsync(user, request.LockoutEnd);
                action = "locked";
            }
            else
            {
                // Unlock the user
                result = await _userManager.SetLockoutEndDateAsync(user, null);
                action = "unlocked";
            }
            
            if (result.Succeeded)
            {
                _logger.LogInformation("User {UserId} {Action} successfully", id, action);
                return (true, action, Enumerable.Empty<string>());
            }

            var errors = result.Errors.Select(e => e.Description);
            _logger.LogWarning("Failed to {Action} user {UserId}: {Errors}", action, id, string.Join(", ", errors));
            return (false, action, errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting lockout for user {UserId}", id);
            return (false, "", new[] { "An error occurred while setting lockout" });
        }
    }
}