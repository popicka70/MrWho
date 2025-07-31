using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore;

namespace MrWho.Handlers;

public interface ITokenHandler
{
    Task<IResult> HandleTokenRequestAsync(HttpContext context);
}

public class TokenHandler : ITokenHandler
{
    private readonly UserManager<IdentityUser> _userManager;

    public TokenHandler(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<IResult> HandleTokenRequestAsync(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Log the grant type for debugging
        Console.WriteLine($"Token request received: GrantType={request.GrantType}, ClientId={request.ClientId}");

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordGrantAsync(request);
        }

        if (request.IsClientCredentialsGrantType())
        {
            return HandleClientCredentialsGrant(request);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            return await HandleAuthorizationCodeGrantAsync(request);
        }

        if (request.IsRefreshTokenGrantType())
        {
            return HandleRefreshTokenGrant(request);
        }

        throw new InvalidOperationException($"The specified grant type '{request.GrantType}' is not supported.");
    }

    private async Task<IResult> HandlePasswordGrantAsync(OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username!);

        if (user != null && await _userManager.CheckPasswordAsync(user, request.Password!))
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
            identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email!);
            identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);
            identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    private static IResult HandleClientCredentialsGrant(OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId!);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IResult> HandleAuthorizationCodeGrantAsync(OpenIddictRequest request)
    {
        // For authorization code flow, OpenIddict handles most of the work automatically
        // We just need to create the identity with the user's claims
        
        // In a typical authorization code flow, the user has already been authenticated
        // during the authorization step, so we don't need to re-authenticate them here
        
        // Create a basic identity - in a real application, you would retrieve the user
        // information from the authorization code or from a stored context
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        
        // For now, use a placeholder subject - this should be replaced with actual user identification
        // In a production app, you would extract the user ID from the authorization code context
        identity.AddClaim(OpenIddictConstants.Claims.Subject, "authorized_user");
        identity.AddClaim(OpenIddictConstants.Claims.Name, "Authorized User");
        identity.AddClaim(OpenIddictConstants.Claims.Email, "user@example.com");
        identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, "user@example.com");
        
        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        await Task.CompletedTask; // Simulate async operation if needed

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IResult HandleRefreshTokenGrant(OpenIddictRequest request)
    {
        // For refresh token flow, we typically want to validate the refresh token
        // and issue new access tokens with the same or updated claims
        
        // Create a basic identity - in a real application, you would validate the refresh token
        // and extract the user information from it
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        
        // For now, use a placeholder subject - this should be replaced with actual user identification
        // In a production app, you would extract the user info from the refresh token
        identity.AddClaim(OpenIddictConstants.Claims.Subject, "refreshed_user");
        identity.AddClaim(OpenIddictConstants.Claims.Name, "Refreshed User");
        identity.AddClaim(OpenIddictConstants.Claims.Email, "user@example.com");
        identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, "user@example.com");
        
        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}