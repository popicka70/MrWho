using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWhoAdmin.Web.Services;

namespace MrWhoAdmin.Web.Controllers;

/// <summary>
/// Controller for handling authentication operations including re-authentication
/// </summary>
public class AuthController : Controller
{
    private readonly ITokenRefreshService _tokenRefreshService;
    private readonly ILogger<AuthController> _logger;
    private const string AdminCookieScheme = "AdminCookies"; // Match the scheme from ServiceCollectionExtensions

    public AuthController(ITokenRefreshService tokenRefreshService, ILogger<AuthController> logger)
    {
        _tokenRefreshService = tokenRefreshService;
        _logger = logger;
    }

    /// <summary>
    /// Endpoint to trigger login/challenge
    /// </summary>
    /// <param name="returnUrl">URL to redirect to after authentication</param>
    /// <returns>Challenge result</returns>
    [HttpGet("/auth/login")]
    public IActionResult Login(string? returnUrl = null)
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
        };

        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme); // Use standard OIDC scheme
    }

    /// <summary>
    /// Endpoint to trigger logout
    /// </summary>
    /// <param name="returnUrl">URL to redirect to after logout</param>
    /// <param name="clearAll">Whether to clear all authentication completely</param>
    /// <returns>SignOut result</returns>
    [HttpGet("/auth/logout")]
    [AllowAnonymous]
    public async Task<IActionResult> Logout(string? returnUrl = null, bool clearAll = false)
    {
        try
        {
            _logger.LogInformation("Admin app logout requested. ReturnUrl: {ReturnUrl}, ClearAll: {ClearAll} (Server-side session isolation active)", returnUrl, clearAll);

            if (clearAll)
            {
                // Perform a proper OIDC sign-out roundtrip to the local OP, while also clearing the local cookie scheme
                var properties = new AuthenticationProperties
                {
                    RedirectUri = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
                };

                _logger.LogInformation("ClearAll: returning OIDC sign-out so OP can cascade external sign-out if needed");

                // IMPORTANT: return SignOut result (do not issue a Redirect here), so middleware can redirect to OP end-session
                return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme, AdminCookieScheme);
            }
            else
            {
                // Standard logout - use standard OIDC scheme (server handles client-specific session isolation)
                if (HttpContext.User.Identity?.IsAuthenticated == true)
                {
                    var properties = new AuthenticationProperties();
                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    {
                        properties.RedirectUri = returnUrl;
                    }
                    
                    _logger.LogInformation("Signing out admin app using standard OIDC (DynamicCookieService handles client isolation)");
                    
                    // Use standard OIDC scheme - server-side DynamicCookieService handles client isolation
                    return SignOut(properties, OpenIdConnectDefaults.AuthenticationScheme, AdminCookieScheme);
                }
                
                var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
                return Redirect(redirectUrl);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during admin app logout");
            var fallbackUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
            return Redirect(fallbackUrl);
        }
    }

    /// <summary>
    /// Endpoint to check if re-authentication is needed and trigger it
    /// </summary>
    /// <param name="returnUrl">URL to redirect to after authentication</param>
    /// <returns>Challenge result or success if token is valid</returns>
    [HttpGet("/auth/check-and-reauth")]
    [Authorize]
    public async Task<IActionResult> CheckAndReauth(string? returnUrl = null)
    {
        try
        {
            _logger.LogInformation("Checking token status and triggering re-authentication if needed");

            // Check if token refresh is needed
            var refreshResult = await _tokenRefreshService.RefreshTokenWithReauthAsync(HttpContext);
            
            if (refreshResult.Success)
            {
                _logger.LogInformation("Token is valid, redirecting to return URL");
                var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
                return Redirect(redirectUrl);
            }
            
            if (refreshResult.RequiresReauth)
            {
                _logger.LogWarning("Re-authentication required. Reason: {Reason}", refreshResult.Reason);
                return await _tokenRefreshService.TriggerReauthenticationAsync(HttpContext, returnUrl);
            }

            _logger.LogWarning("Token refresh failed but re-auth not required. Reason: {Reason}", refreshResult.Reason);
            // Redirect with error indication
            var errorUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) 
                ? $"{returnUrl}?authError=true" 
                : "/?authError=true";
            return Redirect(errorUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during token check and re-authentication");
            return StatusCode(500, "Authentication check failed");
        }
    }

    /// <summary>
    /// Endpoint to force token refresh
    /// </summary>
    /// <param name="returnUrl">URL to redirect to after refresh</param>
    /// <returns>Redirect to return URL or re-authentication challenge</returns>
    [HttpGet("/auth/refresh")]
    [Authorize]
    public async Task<IActionResult> RefreshToken(string? returnUrl = null)
    {
        try
        {
            _logger.LogInformation("Force refreshing token");

            var refreshResult = await _tokenRefreshService.RefreshTokenWithReauthAsync(HttpContext, force: true);
            
            if (refreshResult.Success)
            {
                _logger.LogInformation("Token refresh successful");
                var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
                return Redirect(redirectUrl);
            }
            
            if (refreshResult.RequiresReauth)
            {
                _logger.LogWarning("Token refresh failed, triggering re-authentication. Reason: {Reason}", refreshResult.Reason);
                return await _tokenRefreshService.TriggerReauthenticationAsync(HttpContext, returnUrl);
            }

            _logger.LogWarning("Token refresh failed. Reason: {Reason}", refreshResult.Reason);
            var errorUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) 
                ? $"{returnUrl}?refreshError=true" 
                : "/?refreshError=true";
            return Redirect(errorUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during forced token refresh");
            return StatusCode(500, "Token refresh failed");
        }
    }

    /// <summary>
    /// Simple API endpoint to check authentication status
    /// </summary>
    /// <returns>JSON with authentication status</returns>
    [HttpGet("/auth/status")]
    public async Task<IActionResult> GetAuthStatus()
    {
        try
        {
            var isAuthenticated = HttpContext.User.Identity?.IsAuthenticated == true;
            
            if (!isAuthenticated)
            {
                return Ok(new { authenticated = false });
            }

            var needsRefresh = await _tokenRefreshService.IsTokenExpiredOrExpiringSoonAsync(HttpContext);
            
            return Ok(new 
            { 
                authenticated = true,
                needsRefresh = needsRefresh,
                userName = HttpContext.User.Identity?.Name,
                claims = HttpContext.User.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList()
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking authentication status");
            return Ok(new { authenticated = false, error = ex.Message });
        }
    }
}