using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;

namespace MrWhoAdmin.Web.Controllers;

/// <summary>
/// Handles back-channel logout notifications from the OIDC server
/// </summary>
[ApiController]
[Route("signout-backchannel")]
public class BackChannelLogoutController : ControllerBase
{
    private readonly ILogger<BackChannelLogoutController> _logger;
    private readonly IMemoryCache _cache;

    public BackChannelLogoutController(
        ILogger<BackChannelLogoutController> logger,
        IMemoryCache cache)
    {
        _logger = logger;
        _cache = cache;
    }

    /// <summary>
    /// Handles back-channel logout notifications
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> LogoutNotification([FromForm] string logout_token)
    {
        try
        {
            _logger.LogInformation("Admin Web received back-channel logout notification");

            if (string.IsNullOrEmpty(logout_token))
            {
                _logger.LogWarning("Back-channel logout notification missing logout_token");
                return BadRequest("Missing logout_token");
            }

            // Parse the logout token (in production, verify JWT signature)
            var logoutData = JsonSerializer.Deserialize<JsonElement>(logout_token);
            
            var subject = logoutData.TryGetProperty("sub", out var subElement) ? subElement.GetString() : null;
            var sessionId = logoutData.TryGetProperty("sid", out var sidElement) ? sidElement.GetString() : null;

            _logger.LogInformation("Processing Admin Web logout for subject: {Subject}, session: {SessionId}", subject, sessionId);

            // Store logout information in cache with expiration
            // This allows subsequent requests to detect that the session has been invalidated
            if (!string.IsNullOrEmpty(subject))
            {
                var logoutInfo = new
                {
                    LoggedOutAt = DateTime.UtcNow,
                    Subject = subject,
                    SessionId = sessionId,
                    Reason = "BackChannelLogout"
                };
                
                // Store logout notification for this subject for 1 hour
                // This helps detect invalidated sessions on subsequent requests
                _cache.Set($"logout_{subject}", logoutInfo, TimeSpan.FromHours(1));
                
                // Also store by session ID if available
                if (!string.IsNullOrEmpty(sessionId))
                {
                    _cache.Set($"logout_session_{sessionId}", logoutInfo, TimeSpan.FromHours(1));
                }
            }

            // Force logout by clearing all authentication
            // This will clear the local authentication cookie for this request
            await HttpContext.SignOutAsync("AdminCookies");
            
            // Store logout information in session for any active sessions to detect
            if (HttpContext.Session.IsAvailable)
            {
                HttpContext.Session.SetString("logout_notification", DateTime.UtcNow.ToString());
                if (!string.IsNullOrEmpty(subject))
                {
                    HttpContext.Session.SetString("logout_subject", subject);
                }
                if (!string.IsNullOrEmpty(sessionId))
                {
                    HttpContext.Session.SetString("logout_session_id", sessionId);
                }
            }

            _logger.LogInformation("Admin Web back-channel logout processed successfully for subject: {Subject}", subject);
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing back-channel logout notification in Admin Web");
            return StatusCode(500, "Internal server error");
        }
    }
}