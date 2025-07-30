using Microsoft.AspNetCore.Identity;
using OpenIddict.Server.AspNetCore;

namespace MrWho.Handlers;

/// <summary>
/// Interface for handling OpenID Connect UserInfo requests
/// </summary>
public interface IUserInfoHandler
{
    /// <summary>
    /// Handles UserInfo requests to return user profile information
    /// </summary>
    /// <param name="context">The HTTP context containing the request</param>
    /// <returns>The user info result</returns>
    Task<IResult> HandleUserInfoRequestAsync(HttpContext context);
}

/// <summary>
/// Implementation of UserInfo handler for OpenID Connect UserInfo endpoint
/// </summary>
public class UserInfoHandler : IUserInfoHandler
{
    private readonly UserManager<IdentityUser> _userManager;

    public UserInfoHandler(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    /// <inheritdoc />
    public async Task<IResult> HandleUserInfoRequestAsync(HttpContext context)
    {
        var user = await _userManager.GetUserAsync(context.User);

        if (user == null)
        {
            return Results.Challenge(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        return Results.Ok(new
        {
            sub = user.Id,
            email = user.Email,
            name = user.UserName,
            preferred_username = user.UserName,
            email_verified = user.EmailConfirmed
        });
    }
}