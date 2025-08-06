using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

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
    /// Attempts to refresh the token and indicates if re-authentication is required
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <param name="force">Force refresh even if token is not expired</param>
    /// <returns>Result indicating success and whether re-authentication is needed</returns>
    Task<TokenRefreshResult> RefreshTokenWithReauthAsync(HttpContext httpContext, bool force = false);

    /// <summary>
    /// Triggers re-authentication by clearing cookies and redirecting to login
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <param name="returnUrl">URL to return to after authentication</param>
    /// <returns>Challenge result that redirects to OIDC provider</returns>
    Task<IActionResult> TriggerReauthenticationAsync(HttpContext httpContext, string? returnUrl = null);

    /// <summary>
    /// Checks if the current access token is expired or will expire soon
    /// </summary>
    /// <param name="httpContext">The current HTTP context</param>
    /// <returns>True if token needs refreshing, false otherwise</returns>
    Task<bool> IsTokenExpiredOrExpiringSoonAsync(HttpContext httpContext);
}