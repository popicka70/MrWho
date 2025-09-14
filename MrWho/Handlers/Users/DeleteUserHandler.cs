using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public class DeleteUserHandler : IDeleteUserHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<DeleteUserHandler> _logger;

    public DeleteUserHandler(UserManager<IdentityUser> userManager, ILogger<DeleteUserHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return (false, new[] { $"User with ID '{id}' not found." });
            }

            var result = await _userManager.DeleteAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation("Successfully deleted user {UserName} with ID {UserId}", user.UserName, user.Id);
                return (true, Enumerable.Empty<string>());
            }

            var errors = result.Errors.Select(e => e.Description);
            _logger.LogWarning("Failed to delete user {UserId}: {Errors}", id, string.Join(", ", errors));
            return (false, errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting user {UserId}", id);
            return (false, new[] { "An unexpected error occurred while deleting the user." });
        }
    }
}