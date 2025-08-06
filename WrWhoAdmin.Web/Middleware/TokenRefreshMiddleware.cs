using MrWhoAdmin.Web.Services;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared;

namespace MrWhoAdmin.Web.Middleware;

/// <summary>
/// Middleware to automatically refresh authentication tokens for interactive requests
/// </summary>
public class TokenRefreshMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TokenRefreshMiddleware> _logger;

    public TokenRefreshMiddleware(RequestDelegate next, ILogger<TokenRefreshMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, ITokenRefreshService tokenRefreshService)
    {
        // Only check token refresh for authenticated interactive requests (not API calls)
        // AND avoid refresh during response streaming (Blazor scenarios)
        if (context.User.Identity?.IsAuthenticated == true && 
            IsInteractiveRequest(context) &&
            !IsApiRequest(context) &&
            !context.Response.HasStarted)  // CRITICAL: Don't refresh if response has started
        {
            try
            {
                // First check if we have a refresh token available
                var refreshToken = await context.GetTokenAsync(TokenConstants.TokenNames.RefreshToken);
                if (string.IsNullOrEmpty(refreshToken))
                {
                    // No refresh token available, skip proactive refresh
                    // This is normal for newly authenticated users before they get refresh tokens
                    _logger.LogDebug("No refresh token available for proactive refresh on path: {Path}", context.Request.Path);
                }
                else
                {
                    // Check if token needs refreshing (but only on major page navigations, not every request)
                    if (IsMajorPageNavigation(context) && await tokenRefreshService.IsTokenExpiredOrExpiringSoonAsync(context))
                    {
                        _logger.LogDebug("Token is expired or expiring soon, attempting proactive refresh for path: {Path}", 
                            context.Request.Path);
                        
                        var refreshSuccess = await tokenRefreshService.ForceRefreshTokenAsync(context);
                        if (refreshSuccess)
                        {
                            _logger.LogInformation("Proactive token refresh successful for path: {Path}", 
                                context.Request.Path);
                        }
                        else
                        {
                            _logger.LogWarning("Proactive token refresh failed for path: {Path}. User may need to re-authenticate.", 
                                context.Request.Path);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during proactive token refresh for path: {Path}", context.Request.Path);
                // Don't fail the request due to token refresh issues
            }
        }

        await _next(context);
    }

    /// <summary>
    /// Determines if this is an interactive request that should trigger token refresh
    /// </summary>
    private static bool IsInteractiveRequest(HttpContext context)
    {
        // Only refresh for GET requests to avoid issues with POST data
        if (!string.Equals(context.Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Skip refresh for static resources
        var path = context.Request.Path.Value?.ToLowerInvariant();
        if (path != null && (
            path.EndsWith(".css") ||
            path.EndsWith(".js") ||
            path.EndsWith(".ico") ||
            path.EndsWith(".png") ||
            path.EndsWith(".jpg") ||
            path.EndsWith(".gif") ||
            path.EndsWith(".svg") ||
            path.Contains("/_framework/") ||
            path.Contains("/_content/")))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Determines if this is a major page navigation (not AJAX or partial requests)
    /// </summary>
    private static bool IsMajorPageNavigation(HttpContext context)
    {
        // Skip refresh on AJAX requests or partial updates
        var headers = context.Request.Headers;
        
        // Check for AJAX indicators
        if (headers.ContainsKey("X-Requested-With") || 
            headers.ContainsKey("HX-Request") || // htmx
            headers.ContainsKey("X-CSRF-TOKEN"))
        {
            return false;
        }

        // Check for Blazor SignalR requests
        var path = context.Request.Path.Value?.ToLowerInvariant();
        if (path != null && (
            path.Contains("/_blazor/") ||
            path.Contains("/hub/") ||
            path.Contains("negotiate")))
        {
            return false;
        }

        // Only refresh on full page navigations
        return true;
    }

    /// <summary>
    /// Determines if this is an API request
    /// </summary>
    private static bool IsApiRequest(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant();
        return path != null && path.StartsWith("/api/");
    }
}