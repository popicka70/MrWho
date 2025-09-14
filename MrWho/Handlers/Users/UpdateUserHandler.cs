using Microsoft.AspNetCore.Identity;
using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public class UpdateUserHandler : IUpdateUserHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<UpdateUserHandler> _logger;

    public UpdateUserHandler(UserManager<IdentityUser> userManager, ILogger<UpdateUserHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<(bool Success, UserDto? User, IEnumerable<string> Errors)> HandleAsync(string id, UpdateUserRequest request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return (false, null, new[] { $"User with ID '{id}' not found." });
            }

            var errors = new List<string>();

            // Update properties if provided
            if (!string.IsNullOrEmpty(request.UserName) && request.UserName != user.UserName)
            {
                var setUserNameResult = await _userManager.SetUserNameAsync(user, request.UserName);
                if (!setUserNameResult.Succeeded)
                {
                    errors.AddRange(setUserNameResult.Errors.Select(e => e.Description));
                }
            }

            if (!string.IsNullOrEmpty(request.Email) && request.Email != user.Email)
            {
                var setEmailResult = await _userManager.SetEmailAsync(user, request.Email);
                if (!setEmailResult.Succeeded)
                {
                    errors.AddRange(setEmailResult.Errors.Select(e => e.Description));
                }
            }

            if (!string.IsNullOrEmpty(request.PhoneNumber) && request.PhoneNumber != user.PhoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, request.PhoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    errors.AddRange(setPhoneResult.Errors.Select(e => e.Description));
                }
            }

            // Update boolean properties directly
            if (request.EmailConfirmed.HasValue && request.EmailConfirmed.Value != user.EmailConfirmed)
            {
                user.EmailConfirmed = request.EmailConfirmed.Value;
            }

            if (request.PhoneNumberConfirmed.HasValue && request.PhoneNumberConfirmed.Value != user.PhoneNumberConfirmed)
            {
                user.PhoneNumberConfirmed = request.PhoneNumberConfirmed.Value;
            }

            if (request.TwoFactorEnabled.HasValue && request.TwoFactorEnabled.Value != user.TwoFactorEnabled)
            {
                var setTwoFactorResult = await _userManager.SetTwoFactorEnabledAsync(user, request.TwoFactorEnabled.Value);
                if (!setTwoFactorResult.Succeeded)
                {
                    errors.AddRange(setTwoFactorResult.Errors.Select(e => e.Description));
                }
            }

            // Update the user
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                errors.AddRange(updateResult.Errors.Select(e => e.Description));
            }

            if (errors.Any())
            {
                _logger.LogWarning("Failed to update user {UserId}: {Errors}", id, string.Join(", ", errors));
                return (false, null, errors);
            }

            _logger.LogInformation("Successfully updated user {UserName} with ID {UserId}", user.UserName, user.Id);

            var userDto = new UserDto
            {
                Id = user.Id,
                UserName = user.UserName!,
                Email = user.Email!,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnabled = user.LockoutEnabled,
                LockoutEnd = user.LockoutEnd,
                AccessFailedCount = user.AccessFailedCount
            };

            return (true, userDto, Enumerable.Empty<string>());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user {UserId}", id);
            return (false, null, new[] { "An unexpected error occurred while updating the user." });
        }
    }
}
