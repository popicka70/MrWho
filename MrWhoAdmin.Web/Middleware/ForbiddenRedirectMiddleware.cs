using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace MrWhoAdmin.Web.Middleware;

/// <summary>
/// Middleware to handle 403 Forbidden responses and automatically trigger logout
/// </summary>
public class ForbiddenRedirectMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ForbiddenRedirectMiddleware> _logger;
    private const string AdminCookieScheme = "AdminCookies";

    public ForbiddenRedirectMiddleware(RequestDelegate next, ILogger<ForbiddenRedirectMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        await _next(context);

        // Check if this is a 403 Forbidden response
        if (context.Response.StatusCode == 403 && !context.Response.HasStarted)
        {
            var requestPath = context.Request.Path.Value?.ToLowerInvariant() ?? "";
            
            // Don't redirect if we're already on an auth-related page to prevent loops
            if (requestPath.StartsWith("/auth/") || 
                requestPath.StartsWith("/login") || 
                requestPath.StartsWith("/logout") ||
                requestPath.StartsWith("/signin-oidc") ||
                requestPath.StartsWith("/signout-") ||
                requestPath.StartsWith("/connect/")) // CRITICAL: Don't interfere with OIDC endpoints
            {
                return;
            }

            // Don't redirect for API calls, static resources, or Blazor SignalR hubs
            if (requestPath.StartsWith("/api/") || 
                requestPath.StartsWith("/_blazor") ||
                requestPath.StartsWith("/_framework") ||
                requestPath.Contains(".") || // Static files
                context.Request.Headers.Accept.ToString().Contains("application/json") ||
                context.Request.Headers.Accept.ToString().Contains("text/plain"))
            {
                return;
            }

            _logger.LogWarning("403 Forbidden detected on path {Path}, triggering automatic logout", requestPath);

            try
            {
                // Clear the authentication cookies immediately
                await context.SignOutAsync(AdminCookieScheme);
                
                // Check if this is a Blazor Server request
                var isBlazorRequest = context.Request.Headers.ContainsKey("X-Requested-With") ||
                                     requestPath.StartsWith("/_blazor") ||
                                     context.Request.Headers.Accept.ToString().Contains("text/html");

                if (isBlazorRequest)
                {
                    // For Blazor requests, return a response that triggers client-side redirect
                    context.Response.StatusCode = 403;
                    context.Response.Headers.Add("X-Auth-Error", "session_revoked");
                    context.Response.Headers.Add("X-Auth-Error-Redirect", "/auth/error?error=access_denied&status_code=403");
                    await context.Response.WriteAsync("Authentication required");
                }
                else
                {
                    // For regular requests, redirect normally
                    var errorUrl = "/auth/error?" +
                                  $"error=access_denied&" +
                                  $"error_description=Session expired or access denied&" +
                                  $"status_code=403&" +
                                  $"original_path={Uri.EscapeDataString(requestPath)}";

                    _logger.LogInformation("Redirecting to authentication error page: {ErrorUrl}", errorUrl);
                    context.Response.Redirect(errorUrl);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during automatic logout redirect for 403");
                
                // Fallback: simple redirect to auth error
                try
                {
                    context.Response.Redirect("/auth/error?error=access_denied&status_code=403");
                }
                catch (Exception fallbackEx)
                {
                    _logger.LogError(fallbackEx, "Fallback redirect also failed");
                }
            }
        }
    }
}