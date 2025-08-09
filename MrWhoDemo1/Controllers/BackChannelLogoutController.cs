using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace MrWhoDemo1.Controllers;

/// <summary>
/// Handles back-channel logout notifications from the OIDC server
/// </summary>
[ApiController]
[Route("signout-backchannel")]
public class BackChannelLogoutController : ControllerBase
{
    private readonly ILogger<BackChannelLogoutController> _logger;

    public BackChannelLogoutController(ILogger<BackChannelLogoutController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Handles back-channel logout notifications
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> LogoutNotification([FromForm] string logout_token)
    {
        try
        {
            _logger.LogInformation("Received back-channel logout notification");

            if (string.IsNullOrEmpty(logout_token))
            {
                _logger.LogWarning("Back-channel logout notification missing logout_token");
                return BadRequest("Missing logout_token");
            }

            // Parse the logout token (in production, verify JWT signature)
            var logoutData = JsonSerializer.Deserialize<JsonElement>(logout_token);
            
            var subject = logoutData.TryGetProperty("sub", out var subElement) ? subElement.GetString() : null;
            var sessionId = logoutData.TryGetProperty("sid", out var sidElement) ? sidElement.GetString() : null;

            _logger.LogInformation("Processing logout for subject: {Subject}, session: {SessionId}", subject, sessionId);

            // Force logout by clearing all authentication
            // This will clear the local authentication cookie
            await HttpContext.SignOutAsync("Demo1Cookies");
            
            // Store logout information for any active sessions to detect
            if (HttpContext.Session.IsAvailable)
            {
                HttpContext.Session.SetString("logout_notification", DateTime.UtcNow.ToString());
                if (!string.IsNullOrEmpty(subject))
                {
                    HttpContext.Session.SetString("logout_subject", subject);
                }
            }

            _logger.LogInformation("Back-channel logout processed successfully for subject: {Subject}", subject);
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing back-channel logout notification");
            return StatusCode(500, "Internal server error");
        }
    }
}