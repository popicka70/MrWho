using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWhoAdmin.Web.Services;
using MrWhoAdmin.Web.Extensions;

namespace MrWhoAdmin.Web.Controllers;

/// <summary>
/// Controller for handling authentication operations including re-authentication
/// </summary>
public class AuthController : Controller
{
    private readonly ITokenRefreshService _tokenRefreshService;
    private readonly ILogger<AuthController> _logger;
    private readonly IAdminProfileService _profiles;
    private const string AdminCookieScheme = "AdminCookies"; // legacy single-profile

    public AuthController(ITokenRefreshService tokenRefreshService, ILogger<AuthController> logger, IAdminProfileService profiles)
    {
        _tokenRefreshService = tokenRefreshService;
        _logger = logger;
        _profiles = profiles;
    }

    private (string cookieScheme, string oidcScheme)? ResolveSchemes()
    {
        var list = _profiles.GetProfiles();
        var current = _profiles.GetCurrentProfile(HttpContext);
        if (current == null)
        {
            if (list.Count <= 1)
            {
                // Single profile mode without selection cookie yet – still allow default challenge
                return (AdminCookieScheme, OpenIdConnectDefaults.AuthenticationScheme);
            }
            return null; // multi profile but none selected
        }
        if (list.Count <= 1)
        {
            // In single profile mode we intentionally configured standard schemes, not dynamic ones
            return (AdminCookieScheme, OpenIdConnectDefaults.AuthenticationScheme);
        }
        // Multi-profile: dynamic naming
        return (_profiles.GetCookieScheme(current), _profiles.GetOidcScheme(current));
    }

    /// <summary>
    /// Endpoint to trigger login/challenge
    /// </summary>
    /// <param name="returnUrl">URL to redirect to after authentication</param>
    /// <param name="force">If true, force a fresh sign-in (prompt=login) at the OP and upstream IdP</param>
    /// <returns>Challenge result</returns>
    [HttpGet("/auth/login")]
    public IActionResult Login(string? returnUrl = null, bool force = false)
    {
        var schemes = ResolveSchemes();
        if (schemes == null)
        {
            // multi-profile but no selection – go pick one
            if (_profiles.GetProfiles().Count > 1)
                return Redirect("/login");
        }
        var (cookieScheme, oidcScheme) = schemes!.Value;
        var properties = new AuthenticationProperties
        {
            RedirectUri = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
        };
        if (force) properties.Items["force"] = "1";
        _logger.LogInformation("Initiating login using scheme {Scheme} (cookie={Cookie})", oidcScheme, cookieScheme);
        return Challenge(properties, oidcScheme);
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
            var schemes = ResolveSchemes();
            if (schemes == null)
            {
                return Redirect(LocalRedirectUrl(returnUrl));
            }
            var (cookie, oidc) = schemes.Value;
            _logger.LogInformation("Logout requested (profile={Profile}) cookie={Cookie} oidc={Oidc}", _profiles.GetCurrentProfile(HttpContext)?.Name, cookie, oidc);
            var properties = new AuthenticationProperties { RedirectUri = LocalRedirectUrl(returnUrl) };
            if (clearAll || HttpContext.User.Identity?.IsAuthenticated == true)
            {
                return SignOut(properties, oidc, cookie);
            }
            return Redirect(LocalRedirectUrl(returnUrl));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return Redirect(LocalRedirectUrl(returnUrl));
        }
    }

    private string LocalRedirectUrl(string? returnUrl) => !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";

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
            var refreshResult = await _tokenRefreshService.RefreshTokenWithReauthAsync(HttpContext);
            if (refreshResult.Success)
            {
                return Redirect(LocalRedirectUrl(returnUrl));
            }
            if (refreshResult.RequiresReauth)
            {
                return await _tokenRefreshService.TriggerReauthenticationAsync(HttpContext, returnUrl);
            }
            return Redirect(LocalRedirectUrl(returnUrl) + "?authError=true");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during check-and-reauth");
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
            var refreshResult = await _tokenRefreshService.RefreshTokenWithReauthAsync(HttpContext, force: true);
            if (refreshResult.Success)
                return Redirect(LocalRedirectUrl(returnUrl));
            if (refreshResult.RequiresReauth)
                return await _tokenRefreshService.TriggerReauthenticationAsync(HttpContext, returnUrl);
            return Redirect(LocalRedirectUrl(returnUrl) + "?refreshError=true");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during refresh");
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
                return Ok(new { authenticated = false, profile = _profiles.GetCurrentProfile(HttpContext)?.Name });
            }
            var needsRefresh = await _tokenRefreshService.IsTokenExpiredOrExpiringSoonAsync(HttpContext);
            return Ok(new
            {
                authenticated = true,
                needsRefresh,
                profile = _profiles.GetCurrentProfile(HttpContext)?.Name,
                userName = HttpContext.User.Identity?.Name,
                claims = HttpContext.User.Claims.Select(c => new { type = c.Type, value = c.Value }).ToList()
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking auth status");
            return Ok(new { authenticated = false, error = ex.Message });
        }
    }
}