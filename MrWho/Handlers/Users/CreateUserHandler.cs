using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public class CreateUserHandler : ICreateUserHandler
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ILogger<CreateUserHandler> _logger;

    public CreateUserHandler(UserManager<IdentityUser> userManager, ILogger<CreateUserHandler> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<(bool Success, UserDto? User, IEnumerable<string> Errors)> HandleAsync(CreateUserRequest request)
    {
        try
        {
            var user = new IdentityUser
            {
                UserName = request.UserName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                EmailConfirmed = request.EmailConfirmed ?? false,
                PhoneNumberConfirmed = request.PhoneNumberConfirmed ?? false,
                TwoFactorEnabled = request.TwoFactorEnabled ?? false
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("Successfully created user {UserName} with ID {UserId}", user.UserName, user.Id);
                
                var userDto = new UserDto
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
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

            var errors = result.Errors.Select(e => e.Description);
            _logger.LogWarning("Failed to create user {UserName}: {Errors}", request.UserName, string.Join(", ", errors));
            return (false, null, errors);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user {UserName}", request.UserName);
            return (false, null, new[] { "An unexpected error occurred while creating the user." });
        }
    }
}