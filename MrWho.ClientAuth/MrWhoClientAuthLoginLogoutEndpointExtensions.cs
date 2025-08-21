using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection; // for DI abstractions

namespace MrWho.ClientAuth;

/// <summary>
/// Front-channel login & logout endpoint helpers for MrWho client apps.
/// These are optional convenience endpoints. Applications can always call
/// HttpContext.ChallengeAsync / SignOutAsync directly instead.
/// </summary>
public static class MrWhoClientAuthLoginLogoutEndpointExtensions
{
    /// <summary>
    /// Maps a /login style endpoint that issues an OpenID Connect challenge.
    /// Query string: ?returnUrl=/relative/path (defaults to "/").
    /// </summary>
    public static IEndpointConventionBuilder MapMrWhoLoginEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/login")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (string.IsNullOrWhiteSpace(pattern)) pattern = "/login";

        return endpoints.MapGet(pattern, async context =>
        {
            var returnUrl = context.Request.Query["returnUrl"].ToString();
            if (string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
                returnUrl = "/";

            var provider = (IAuthenticationSchemeProvider?)context.RequestServices.GetService(typeof(IAuthenticationSchemeProvider));
            var challengeScheme = provider is null ? null : await provider.GetDefaultChallengeSchemeAsync();
            if (challengeScheme is null)
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("No default challenge scheme configured.");
                return;
            }

            var props = new AuthenticationProperties { RedirectUri = returnUrl };
            await context.ChallengeAsync(challengeScheme.Name, props);
        })
        .WithDisplayName("MrWho Login");
    }

    /// <summary>
    /// Maps /logout endpoint(s) that perform local cookie sign-out and, if configured, remote OIDC sign-out.
    /// Supports both GET and POST. Query string: ?returnUrl=/relative/path (defaults to "/").
    /// </summary>
    /// <remarks>
    /// Sign-out flow:
    /// 1. Signs out the default authenticate scheme (cookie) if present.
    /// 2. Signs out using the default sign-out scheme; if none, tries default challenge scheme (OIDC) for upstream logout.
    /// 3. Redirects back to returnUrl afterwards.
    /// </remarks>
    public static IEndpointRouteBuilder MapMrWhoLogoutEndpoints(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/logout")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (string.IsNullOrWhiteSpace(pattern)) pattern = "/logout";

        async Task Handle(HttpContext context)
        {
            var returnUrl = context.Request.Query["returnUrl"].ToString();
            if (string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
                returnUrl = "/";

            var provider = (IAuthenticationSchemeProvider?)context.RequestServices.GetService(typeof(IAuthenticationSchemeProvider));
            if (provider is null)
            {
                context.Response.Redirect(returnUrl);
                return;
            }

            var defaultAuth = await provider.GetDefaultAuthenticateSchemeAsync();
            var signOutScheme = await provider.GetDefaultSignOutSchemeAsync() ?? await provider.GetDefaultChallengeSchemeAsync();

            if (defaultAuth is not null)
            {
                await context.SignOutAsync(defaultAuth.Name);
            }

            if (signOutScheme is not null)
            {
                // Avoid double sign-out if both point to same underlying scheme (e.g., only cookies).
                if (defaultAuth?.Name != signOutScheme.Name)
                {
                    var props = new AuthenticationProperties { RedirectUri = returnUrl };
                    await context.SignOutAsync(signOutScheme.Name, props);
                    return; // Upstream handler will handle redirect.
                }
            }

            // Fallback local redirect.
            context.Response.Redirect(returnUrl);
        }

        endpoints.MapGet(pattern, Handle).WithDisplayName("MrWho Logout (GET)");
        endpoints.MapPost(pattern, Handle).WithDisplayName("MrWho Logout (POST)");
        return endpoints;
    }
}
