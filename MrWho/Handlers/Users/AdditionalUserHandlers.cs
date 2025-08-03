using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public class ResetPasswordHandler : IResetPasswordHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<ResetPasswordHandler> _logger;

    public ResetPasswordHandler(UserManager<IdentityUser> userManager, ILogger<ResetPasswordHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id, ResetPasswordRequest request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return (false, new[] { "User not found" });
            }

            // Remove current password (admin reset)
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
            
            if (result.Succeeded)
            {
                _logger.LogInformation("Password reset successfully for user {UserId}", id);
                return (true, Enumerable.Empty<string>());
            }

            var errors = result.Errors.Select(e => e.Description);
            _logger.LogWarning("Failed to reset password for user {UserId}: {Errors}", id, string.Join(", ", errors));
            return (false, errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for user {UserId}", id);
            return (false, new[] { "An error occurred while resetting the password" });
        }
    }
}

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