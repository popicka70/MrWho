using MrWho.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using MrWho.Options;
using Microsoft.AspNetCore.Identity;

namespace MrWho.Middleware;

/// <summary>
/// Middleware to handle client-specific cookie schemes for OIDC authentication
/// </summary>
public class ClientCookieMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ClientCookieMiddleware> _logger;
    private readonly MrWhoOptions _options;

    public ClientCookieMiddleware(RequestDelegate next, ILogger<ClientCookieMiddleware> logger, IOptions<MrWhoOptions> options)
    {
        _next = next;
        _logger = logger;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context, IClientCookieConfigurationService cookieService)
    {
        // Only process requests for OIDC endpoints or when client_id is present
        if (IsOidcEndpoint(context.Request.Path) || HasClientIdParameter(context))
        {
            var clientId = await cookieService.GetClientIdFromRequestAsync(context);
            if (!string.IsNullOrEmpty(clientId))
            {
                var cookieScheme = cookieService.GetCookieSchemeForClient(clientId);
                var cookieName = cookieService.GetCookieNameForClient(clientId);
                
                // Store client information in context for use by other components
                context.Items["ClientCookieScheme"] = cookieScheme;
                context.Items["ClientId"] = clientId;
                context.Items["ClientCookieName"] = cookieName;
                
                _logger.LogDebug("Using cookie scheme {Scheme} (cookie: {CookieName}) for client {ClientId} on path {Path}", 
                    cookieScheme, cookieName, clientId, context.Request.Path);

                // Store client_id in session for callback scenarios (only if session is configured)
                var hasSession = context.Features.Get<ISessionFeature>() is not null;
                if (hasSession && 
                    (context.Request.Path.StartsWithSegments("/connect/authorize") ||
                     context.Request.Path.StartsWithSegments("/login")))
                {
                    if (context.Session.IsAvailable)
                    {
                        context.Session.SetString("oidc_client_id", clientId);
                    }
                }
            }
            else if (_options.CookieSeparationMode == MrWho.Options.CookieSeparationMode.None)
            {
                // In None mode, set standard scheme and cookie name to ensure consistent behavior
                context.Items["ClientCookieScheme"] = IdentityConstants.ApplicationScheme;
                context.Items["ClientCookieName"] = ".AspNetCore.Identity.Application";
            }
        }

        await _next(context);
    }

    private static bool IsOidcEndpoint(PathString path)
    {
        return path.StartsWithSegments("/connect") || 
               path.StartsWithSegments("/.well-known") ||
               path.StartsWithSegments("/signin-oidc") ||
               path.StartsWithSegments("/signout-oidc") ||
               path.StartsWithSegments("/signout-callback-oidc");
    }

    private static bool HasClientIdParameter(HttpContext context)
    {
        return context.Request.Query.ContainsKey("client_id") ||
               (context.Request.HasFormContentType && context.Request.Form.ContainsKey("client_id"));
    }
}