using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public class ChangePasswordHandler : IChangePasswordHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<ChangePasswordHandler> _logger;

    public ChangePasswordHandler(UserManager<IdentityUser> userManager, ILogger<ChangePasswordHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id, ChangePasswordRequest request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return (false, new[] { "User not found" });
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);

            if (result.Succeeded)
            {
                _logger.LogInformation("Password changed successfully for user {UserId}", id);
                return (true, Enumerable.Empty<string>());
            }

            var errors = result.Errors.Select(e => e.Description);
            _logger.LogWarning("Failed to change password for user {UserId}: {Errors}", id, string.Join(", ", errors));
            return (false, errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error changing password for user {UserId}", id);
            return (false, new[] { "An error occurred while changing the password" });
        }
    }
}