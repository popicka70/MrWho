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
