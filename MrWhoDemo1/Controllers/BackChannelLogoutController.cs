using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace MrWhoDemo1.Controllers;

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
            _logger.LogInformation("Demo1 received back-channel logout notification");

            if (string.IsNullOrEmpty(logout_token))
            {
                _logger.LogWarning("Back-channel logout notification missing logout_token");
                return BadRequest("Missing logout_token");
            }

            string? subject = null;
            string? sessionId = null;

            // Prefer JWT parsing (spec-compliant)
            if (logout_token.Count(c => c == '.') == 2)
            {
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    var jwt = handler.ReadJwtToken(logout_token);
                    subject = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                    sessionId = jwt.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;

                    // Optionally validate events claim presence
                    if (!jwt.Payload.TryGetValue("events", out var eventsObj))
                    {
                        _logger.LogWarning("logout_token missing events claim");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse logout_token as JWT, will try JSON fallback");
                }
            }

            // Fallback: legacy JSON (dev mode, unsigned)
            if (subject == null && sessionId == null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(logout_token);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("sub", out var subElement)) subject = subElement.GetString();
                    if (root.TryGetProperty("sid", out var sidElement)) sessionId = sidElement.GetString();
                }
                catch (Exception jsonEx)
                {
                    _logger.LogError(jsonEx, "Failed to parse logout_token JSON");
                    return BadRequest("Invalid logout_token");
                }
            }

            _logger.LogInformation("Processing Demo1 logout for subject: {Subject}, session: {SessionId}", subject, sessionId);

            // Store logout information in cache with expiration
            if (!string.IsNullOrEmpty(subject))
            {
                var logoutInfo = new
                {
                    LoggedOutAt = DateTime.UtcNow,
                    Subject = subject,
                    SessionId = sessionId,
                    Reason = "BackChannelLogout"
                };

                _cache.Set($"logout_{subject}", logoutInfo, TimeSpan.FromHours(1));

                if (!string.IsNullOrEmpty(sessionId))
                {
                    _cache.Set($"logout_session_{sessionId}", logoutInfo, TimeSpan.FromHours(1));
                }
            }

            // Clear local authentication for this request
            await HttpContext.SignOutAsync("Demo1Cookies");

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

            _logger.LogInformation("Demo1 back-channel logout processed successfully for subject: {Subject}", subject);
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing back-channel logout notification in Demo1");
            return StatusCode(500, "Internal server error");
        }
    }
}