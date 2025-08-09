using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MrWho.Services.Mediator;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore; // Ensures extension methods on HttpContext are visible

namespace MrWho.Endpoints;

public sealed record OidcTokenRequest(HttpContext HttpContext) : IRequest<IResult>;

public sealed class OidcTokenHandler : IRequestHandler<OidcTokenRequest, IResult>
{
    public async Task<IResult> Handle(OidcTokenRequest request, CancellationToken cancellationToken)
    {
        var context = request.HttpContext;
        var oidcRequest = context.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (oidcRequest.IsAuthorizationCodeGrantType())
        {
            var authResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!authResult.Succeeded)
            {
                return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
            }
            return Results.SignIn(authResult.Principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (oidcRequest.IsClientCredentialsGrantType())
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, oidcRequest.ClientId!);
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(oidcRequest.GetScopes());
            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (oidcRequest.IsPasswordGrantType())
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
            var user = await userManager.FindByNameAsync(oidcRequest.Username!);

            if (user != null && await userManager.CheckPasswordAsync(user, oidcRequest.Password!))
            {
                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
                identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email!);
                identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);

                var principal = new ClaimsPrincipal(identity);
                principal.SetScopes(oidcRequest.GetScopes());

                return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
        }

        if (oidcRequest.IsRefreshTokenGrantType())
        {
            var authResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!authResult.Succeeded)
            {
                return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
            }
            return Results.SignIn(authResult.Principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }
}
