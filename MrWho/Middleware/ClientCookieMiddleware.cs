using MrWho.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using MrWho.Options;
using Microsoft.AspNetCore.Identity;
using MrWho.Shared.Authentication; // unify defaults
using Microsoft.AspNetCore.Authentication;

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

    public async Task InvokeAsync(HttpContext context, IClientCookieConfigurationService cookieService, IAuthenticationSchemeProvider schemeProvider)
    {
        // Process requests for OIDC endpoints, when client_id is present, or for any endpoint that might need authentication
        if (IsOidcEndpoint(context.Request.Path) || HasClientIdParameter(context) || RequiresAuthentication(context.Request.Path))
        {
            try
            {
                var clientId = await cookieService.GetClientIdFromRequestAsync(context);
                if (!string.IsNullOrEmpty(clientId))
                {
                    var cookieScheme = cookieService.GetCookieSchemeForClient(clientId);
                    var cookieName = cookieService.GetCookieNameForClient(clientId);
                    
                    // Verify the scheme is actually registered before using it
                    var schemeExists = await schemeProvider.GetSchemeAsync(cookieScheme) != null;
                    if (!schemeExists)
                    {
                        _logger.LogWarning("Cookie scheme {Scheme} for client {ClientId} is not registered, falling back to default", 
                            cookieScheme, clientId);
                        cookieScheme = IdentityConstants.ApplicationScheme;
                        cookieName = CookieSchemeNaming.DefaultCookieName;
                    }
                    
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
                else
                {
                    // No client ID found - set default scheme and cookie name to ensure consistent behavior
                    // This is important for endpoints that require authentication but don't have a specific client context
                    string defaultScheme;
                    string defaultCookieName;
                    
                    if (_options.CookieSeparationMode == MrWho.Options.CookieSeparationMode.None)
                    {
                        // In None mode, use standard Identity scheme
                        defaultScheme = IdentityConstants.ApplicationScheme;
                        defaultCookieName = CookieSchemeNaming.DefaultCookieName;
                    }
                    else
                    {
                        // In ByClient or ByRealm mode, try to use the admin client scheme if available
                        // This allows the admin client or fallback authentication to work
                        var adminScheme = cookieService.GetCookieSchemeForClient("mrwho_admin_web");
                        var adminSchemeExists = await schemeProvider.GetSchemeAsync(adminScheme) != null;
                        
                        if (adminSchemeExists && IsAdminEndpoint(context.Request.Path))
                        {
                            defaultScheme = adminScheme;
                            defaultCookieName = cookieService.GetCookieNameForClient("mrwho_admin_web");
                        }
                        else
                        {
                            // Fall back to standard Identity scheme
                            defaultScheme = IdentityConstants.ApplicationScheme;
                            defaultCookieName = CookieSchemeNaming.DefaultCookieName;
                        }
                    }
                    
                    // Verify the default scheme exists too
                    var defaultSchemeExists = await schemeProvider.GetSchemeAsync(defaultScheme) != null;
                    if (!defaultSchemeExists)
                    {
                        _logger.LogError("Default scheme {Scheme} is not registered, this will cause authentication failures", defaultScheme);
                        // Don't set context items if the scheme doesn't exist
                        await _next(context);
                        return;
                    }
                    
                    context.Items["ClientCookieScheme"] = defaultScheme;
                    context.Items["ClientCookieName"] = defaultCookieName;
                    
                    _logger.LogDebug("No client ID found, using default scheme {Scheme} (cookie: {CookieName}) for path {Path}", 
                        defaultScheme, defaultCookieName, context.Request.Path);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ClientCookieMiddleware for path {Path}", context.Request.Path);
                // Continue processing even if middleware fails - let the auth system handle it
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

    private static bool RequiresAuthentication(PathString path)
    {
        // Endpoints that might require authentication but don't necessarily have a client_id parameter
        return path.StartsWithSegments("/identity") ||
               path.StartsWithSegments("/admin") ||
               path.StartsWithSegments("/account") ||
               path.StartsWithSegments("/profile");
    }

    private static bool IsAdminEndpoint(PathString path)
    {
        return path.StartsWithSegments("/admin") ||
               path.StartsWithSegments("/identity");
    }
}