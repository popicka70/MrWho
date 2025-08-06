using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWhoAdmin.Web.Services;
using MrWho.Shared;

namespace MrWhoAdmin.Web.Controllers;

/// <summary>
/// Controller for handling token refresh operations outside of Blazor context
/// This works around Blazor Server response streaming limitations
/// </summary>
[Authorize]
public class TokenController : Controller
{
    private readonly ITokenRefreshService _tokenRefreshService;
    private readonly ILogger<TokenController> _logger;

    public TokenController(ITokenRefreshService tokenRefreshService, ILogger<TokenController> logger)
    {
        _tokenRefreshService = tokenRefreshService;
        _logger = logger;
    }

    /// <summary>
    /// Refresh token endpoint that works with standard HTTP context (no Blazor streaming)
    /// </summary>
    /// <param name="returnUrl">URL to redirect to after refresh</param>
    /// <returns>Redirect to return URL or error page</returns>
    [HttpGet("/token/refresh")]
    public async Task<IActionResult> RefreshToken(string? returnUrl = null)
    {
        try
        {
            _logger.LogInformation("Starting token refresh via standard HTTP context");

            // Use the standard token refresh method (not Blazor-specific)
            var refreshSuccess = await _tokenRefreshService.ForceRefreshTokenAsync(HttpContext, force: true);

            if (refreshSuccess)
            {
                _logger.LogInformation("Token refresh successful via HTTP context");
                
                // Redirect back to the return URL or default to debug page
                var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) 
                    ? returnUrl 
                    : "/debug-token-refresh";
                
                return Redirect(redirectUrl);
            }
            else
            {
                _logger.LogWarning("Token refresh failed via HTTP context");
                
                // Redirect with error indication
                var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) 
                    ? $"{returnUrl}?refreshError=true" 
                    : "/debug-token-refresh?refreshError=true";
                
                return Redirect(redirectUrl);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during token refresh via HTTP context");
            
            // Redirect with error indication
            var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) 
                ? $"{returnUrl}?refreshError=true" 
                : "/debug-token-refresh?refreshError=true";
            
            return Redirect(redirectUrl);
        }
    }

    /// <summary>
    /// Simple endpoint to check token status
    /// </summary>
    [HttpGet("/token/status")]
    public async Task<IActionResult> TokenStatus()
    {
        try
        {
            var accessToken = await HttpContext.GetTokenAsync(TokenConstants.TokenNames.AccessToken);
            var refreshToken = await HttpContext.GetTokenAsync(TokenConstants.TokenNames.RefreshToken);
            var expiresAt = await HttpContext.GetTokenAsync(TokenConstants.TokenNames.ExpiresAt);
            
            var isExpiring = await _tokenRefreshService.IsTokenExpiredOrExpiringSoonAsync(HttpContext);
            
            return Json(new
            {
                HasAccessToken = !string.IsNullOrEmpty(accessToken),
                HasRefreshToken = !string.IsNullOrEmpty(refreshToken),
                ExpiresAt = expiresAt,
                IsExpiring = isExpiring,
                CurrentTime = DateTimeOffset.UtcNow.ToString("o"),
                AccessTokenPreview = !string.IsNullOrEmpty(accessToken) 
                    ? accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "..." 
                    : null
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting token status");
            return Json(new { Error = ex.Message });
        }
    }
}