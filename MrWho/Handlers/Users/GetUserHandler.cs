using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public class GetUserHandler : IGetUserHandler
{
    private readonly UserManager<IdentityUser> _userManager;

    public GetUserHandler(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<UserDto?> HandleAsync(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return null;
        }

        return new UserDto
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
    }
}