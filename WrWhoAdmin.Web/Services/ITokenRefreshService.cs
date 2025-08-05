using Microsoft.AspNetCore.Authentication;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for automatically refreshing authentication tokens
/// </summary>
public interface ITokenRefreshService
{
    /// <summary>
    /// Checks if the current user's access token needs refreshing and refreshes it if necessary
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <returns>True if token was refreshed or is still valid, false if refresh failed</returns>
    Task<bool> EnsureValidTokenAsync(HttpContext httpContext);

    /// <summary>
    /// Forces a token refresh for the current user
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <param name="force">Force refresh even if token is not expired</param>
    /// <returns>True if refresh was successful, false otherwise</returns>
    Task<bool> ForceRefreshTokenAsync(HttpContext httpContext, bool force = false);

    /// <summary>
    /// Forces a token refresh specifically for Blazor scenarios where response may have started
    /// This method handles the case where cookies cannot be updated due to response streaming
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <returns>True if refresh was successful (even if cookies couldn't be updated), false otherwise</returns>
    Task<bool> ForceRefreshTokenForBlazorAsync(HttpContext httpContext);

    /// <summary>
    /// Checks if the current access token is expired or will expire soon
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <returns>True if token needs refreshing, false otherwise</returns>
    Task<bool> IsTokenExpiredOrExpiringSoonAsync(HttpContext httpContext);
}