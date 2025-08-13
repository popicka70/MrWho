using Microsoft.AspNetCore.Mvc;
using MrWho.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using MrWho.Data;
using MrWho.Services;
using Microsoft.AspNetCore.Identity;
using System.Collections.Immutable;

namespace MrWho.Controllers;

/// <summary>
/// API controller for managing and monitoring active user sessions
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthorizationPolicies.AdminClientApi)] // Require authentication for all session endpoints with AdminClientApi policy
public class SessionsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<SessionsController> _logger;

    public SessionsController(
        ApplicationDbContext context,
        UserManager<IdentityUser> userManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictTokenManager tokenManager,
        IOpenIddictApplicationManager applicationManager,
        ILogger<SessionsController> logger)
    {
        _context = context;
        _userManager = userManager;
        _authorizationManager = authorizationManager;
        _tokenManager = tokenManager;
        _applicationManager = applicationManager;
        _logger = logger;
    }

    /// <summary>
    /// Gets all active sessions across all clients
    /// </summary>
    [HttpGet("active")]
    public async Task<ActionResult<List<ActiveSessionDto>>> GetActiveSessions()
    {
        try
        {
            var sessions = new List<ActiveSessionDto>();

            // Buffer authorizations to avoid nested active DataReaders
            var authorizations = new List<object>();
            await foreach (var authorization in _authorizationManager.ListAsync())
            {
                authorizations.Add(authorization);
            }

            foreach (var authorization in authorizations)
            {
                var status = await _authorizationManager.GetStatusAsync(authorization);
                if (status != OpenIddictConstants.Statuses.Valid)
                    continue;

                var session = await CreateSessionDto(authorization);
                if (session != null)
                {
                    sessions.Add(session);
                }
            }

            // Sort by most recent activity
            return Ok(sessions.OrderByDescending(s => s.LastActivity ?? s.CreatedAt).ToList());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving active sessions");
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Gets active sessions for a specific user
    /// </summary>
    [HttpGet("user/{userId}")]
    public async Task<ActionResult<List<ActiveSessionDto>>> GetUserActiveSessions(string userId)
    {
        try
        {
            var sessions = new List<ActiveSessionDto>();

            // Buffer authorizations to avoid nested active DataReaders
            var authorizations = new List<object>();
            await foreach (var authorization in _authorizationManager.FindBySubjectAsync(userId))
            {
                authorizations.Add(authorization);
            }

            foreach (var authorization in authorizations)
            {
                var status = await _authorizationManager.GetStatusAsync(authorization);
                if (status != OpenIddictConstants.Statuses.Valid)
                    continue;

                var session = await CreateSessionDto(authorization);
                if (session != null)
                {
                    sessions.Add(session);
                }
            }

            return Ok(sessions.OrderByDescending(s => s.LastActivity ?? s.CreatedAt).ToList());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving active sessions for user {UserId}", userId);
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Gets active sessions for a specific client
    /// </summary>
    [HttpGet("client/{clientId}")]
    public async Task<ActionResult<List<ActiveSessionDto>>> GetClientActiveSessions(string clientId)
    {
        try
        {
            var sessions = new List<ActiveSessionDto>();

            // Find the application by client ID
            var application = await _applicationManager.FindByClientIdAsync(clientId);
            if (application == null)
            {
                return NotFound($"Client '{clientId}' not found");
            }

            var applicationId = await _applicationManager.GetIdAsync(application);
            if (string.IsNullOrEmpty(applicationId))
            {
                return NotFound($"Client '{clientId}' has no identifier");
            }

            // Buffer authorizations to avoid nested active DataReaders
            var authorizations = new List<object>();
            await foreach (var authorization in _authorizationManager.FindByApplicationIdAsync(applicationId))
            {
                authorizations.Add(authorization);
            }

            foreach (var authorization in authorizations)
            {
                var status = await _authorizationManager.GetStatusAsync(authorization);
                if (status != OpenIddictConstants.Statuses.Valid)
                    continue;

                var session = await CreateSessionDto(authorization);
                if (session != null)
                {
                    sessions.Add(session);
                }
            }

            return Ok(sessions.OrderByDescending(s => s.LastActivity ?? s.CreatedAt).ToList());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving active sessions for client {ClientId}", clientId);
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Revokes a specific session (authorization and all related tokens)
    /// </summary>
    [HttpDelete("{authorizationId}")]
    public async Task<ActionResult> RevokeSession(string authorizationId)
    {
        try
        {
            if (string.IsNullOrEmpty(authorizationId))
            {
                return BadRequest("Authorization id is required");
            }

            var authorization = await _authorizationManager.FindByIdAsync(authorizationId);
            if (authorization == null)
            {
                return NotFound($"Session '{authorizationId}' not found");
            }

            var subject = await _authorizationManager.GetSubjectAsync(authorization);
            var sessionId = authorizationId; // Use authorization ID as session ID

            // Revoke all tokens associated with this authorization
            await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(authorizationId))
            {
                await _tokenManager.TryRevokeAsync(token);
            }

            // Mark the authorization as revoked
            await _authorizationManager.TryRevokeAsync(authorization);

            // CRITICAL: Send back-channel logout notifications to clients
            var backChannelService = HttpContext.RequestServices.GetRequiredService<IBackChannelLogoutService>();
            if (!string.IsNullOrEmpty(subject))
            {
                await backChannelService.NotifyClientLogoutAsync(authorizationId, subject, sessionId);
            }

            _logger.LogInformation("Session {AuthorizationId} revoked successfully with back-channel logout notifications", authorizationId);
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking session {AuthorizationId}", authorizationId);
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Revokes all sessions for a specific user
    /// </summary>
    [HttpDelete("user/{userId}")]
    public async Task<ActionResult> RevokeAllUserSessions(string userId)
    {
        try
        {
            var revokedCount = 0;
            var backChannelService = HttpContext.RequestServices.GetRequiredService<IBackChannelLogoutService>();

            // Buffer authorizations to avoid nested active DataReaders
            var authorizations = new List<object>();
            await foreach (var authorization in _authorizationManager.FindBySubjectAsync(userId))
            {
                authorizations.Add(authorization);
            }

            foreach (var authorization in authorizations)
            {
                var status = await _authorizationManager.GetStatusAsync(authorization);
                if (status != OpenIddictConstants.Statuses.Valid)
                    continue;

                var authorizationId = await _authorizationManager.GetIdAsync(authorization);
                if (string.IsNullOrEmpty(authorizationId))
                {
                    continue;
                }

                // Revoke all tokens associated with this authorization
                await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(authorizationId))
                {
                    await _tokenManager.TryRevokeAsync(token);
                }

                // Mark the authorization as revoked
                await _authorizationManager.TryRevokeAsync(authorization);
                revokedCount++;

                // Send back-channel logout notification for this specific session
                await backChannelService.NotifyClientLogoutAsync(authorizationId, userId, authorizationId);
            }

            _logger.LogInformation("Revoked {Count} sessions for user {UserId} with back-channel logout notifications", revokedCount, userId);
            return Ok(new { RevokedSessions = revokedCount });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking all sessions for user {UserId}", userId);
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Revokes all sessions for a specific client
    /// </summary>
    [HttpDelete("client/{clientId}")]
    public async Task<ActionResult> RevokeAllClientSessions(string clientId)
    {
        try
        {
            // Find the application by client ID
            var application = await _applicationManager.FindByClientIdAsync(clientId);
            if (application == null)
            {
                return NotFound($"Client '{clientId}' not found");
            }

            var applicationId = await _applicationManager.GetIdAsync(application);
            if (string.IsNullOrEmpty(applicationId))
            {
                return NotFound($"Client '{clientId}' has no identifier");
            }
            var revokedCount = 0;

            // Buffer authorizations to avoid nested active DataReaders
            var authorizations = new List<object>();
            await foreach (var authorization in _authorizationManager.FindByApplicationIdAsync(applicationId))
            {
                authorizations.Add(authorization);
            }

            foreach (var authorization in authorizations)
            {
                var status = await _authorizationManager.GetStatusAsync(authorization);
                if (status != OpenIddictConstants.Statuses.Valid)
                    continue;

                var authorizationId = await _authorizationManager.GetIdAsync(authorization);
                if (string.IsNullOrEmpty(authorizationId))
                {
                    continue;
                }

                // Revoke all tokens associated with this authorization
                await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(authorizationId))
                {
                    await _tokenManager.TryRevokeAsync(token);
                }

                // Mark the authorization as revoked
                await _authorizationManager.TryRevokeAsync(authorization);
                revokedCount++;
            }

            _logger.LogInformation("Revoked {Count} sessions for client {ClientId}", revokedCount, clientId);
            return Ok(new { RevokedSessions = revokedCount });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking all sessions for client {ClientId}", clientId);
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Gets session statistics
    /// </summary>
    [HttpGet("statistics")]
    public async Task<ActionResult<SessionStatisticsDto>> GetSessionStatistics()
    {
        try
        {
            var stats = new SessionStatisticsDto();
            var uniqueUsers = new HashSet<string>();
            var clientSessions = new Dictionary<string, int>();
            var sessionTypes = new Dictionary<string, int>();
            var now = DateTime.UtcNow;
            var todayStart = now.Date;
            var weekStart = todayStart.AddDays(-(int)todayStart.DayOfWeek);

            DateTimeOffset? oldestSession = null;
            DateTimeOffset? newestSession = null;

            // Buffer authorizations to avoid nested active DataReaders
            var authorizations = new List<object>();
            await foreach (var authorization in _authorizationManager.ListAsync())
            {
                authorizations.Add(authorization);
            }

            foreach (var authorization in authorizations)
            {
                var status = await _authorizationManager.GetStatusAsync(authorization);
                if (status != OpenIddictConstants.Statuses.Valid)
                    continue;

                stats.TotalActiveSessions++;

                var subject = await _authorizationManager.GetSubjectAsync(authorization);
                if (!string.IsNullOrEmpty(subject))
                {
                    uniqueUsers.Add(subject);
                }

                var applicationId = await _authorizationManager.GetApplicationIdAsync(authorization);
                if (!string.IsNullOrEmpty(applicationId))
                {
                    var application = await _applicationManager.FindByIdAsync(applicationId);
                    if (application != null)
                    {
                        var clientId = await _applicationManager.GetClientIdAsync(application);
                        if (!string.IsNullOrEmpty(clientId))
                        {
                            clientSessions[clientId] = clientSessions.GetValueOrDefault(clientId, 0) + 1;
                            
                            // Determine session type based on client
                            var sessionType = DetermineSessionType(clientId);
                            sessionTypes[sessionType] = sessionTypes.GetValueOrDefault(sessionType, 0) + 1;
                        }
                    }
                }

                var creationDate = await _authorizationManager.GetCreationDateAsync(authorization);
                if (creationDate.HasValue)
                {
                    if (oldestSession == null || creationDate < oldestSession)
                        oldestSession = creationDate;
                    
                    if (newestSession == null || creationDate > newestSession)
                        newestSession = creationDate;

                    if (creationDate.Value.DateTime >= todayStart)
                        stats.SessionsToday++;
                    
                    if (creationDate.Value.DateTime >= weekStart)
                        stats.SessionsThisWeek++;
                }

                // Check for tokens expiring soon (next hour)
                var authorizationId = await _authorizationManager.GetIdAsync(authorization);
                if (!string.IsNullOrEmpty(authorizationId))
                {
                    await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(authorizationId))
                    {
                        var expirationDate = await _tokenManager.GetExpirationDateAsync(token);
                        if (expirationDate.HasValue && expirationDate <= DateTimeOffset.UtcNow.AddHours(1))
                        {
                            stats.ExpiringSoon++;
                            break; // Only count once per session
                        }
                    }
                }
            }

            stats.UniqueActiveUsers = uniqueUsers.Count;
            stats.ActiveClients = clientSessions.Count;
            stats.SessionsByClient = clientSessions;
            stats.SessionsByType = sessionTypes;
            stats.OldestSession = oldestSession?.DateTime ?? DateTime.UtcNow;
            stats.MostRecentSession = newestSession?.DateTime;

            return Ok(stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving session statistics");
            return StatusCode(500, "Internal server error");
        }
    }

    /// <summary>
    /// Creates a session DTO from an OpenIddict authorization
    /// </summary>
    private async Task<ActiveSessionDto?> CreateSessionDto(object authorization)
    {
        try
        {
            var id = await _authorizationManager.GetIdAsync(authorization);
            var subject = await _authorizationManager.GetSubjectAsync(authorization);
            var applicationId = await _authorizationManager.GetApplicationIdAsync(authorization);
            var scopes = await _authorizationManager.GetScopesAsync(authorization);
            var creationDate = await _authorizationManager.GetCreationDateAsync(authorization);

            if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(applicationId))
                return null;

            // Get user information
            var user = await _userManager.FindByIdAsync(subject);
            if (user == null)
                return null;

            // Get application information
            var application = await _applicationManager.FindByIdAsync(applicationId);
            if (application == null)
                return null;

            var clientId = await _applicationManager.GetClientIdAsync(application);
            var clientName = await _applicationManager.GetDisplayNameAsync(application) ?? clientId;

            // Count tokens for this authorization
            var tokenCount = 0;
            var hasRefreshToken = false;
            DateTimeOffset? lastActivity = null;
            DateTimeOffset? expiresAt = null;

            if (!string.IsNullOrEmpty(id))
            {
                await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(id))
                {
                    var tokenStatus = await _tokenManager.GetStatusAsync(token);
                    if (tokenStatus == OpenIddictConstants.Statuses.Valid)
                    {
                        tokenCount++;

                        var tokenType = await _tokenManager.GetTypeAsync(token);
                        if (tokenType == "refresh_token")
                        {
                            hasRefreshToken = true;
                        }

                        var tokenCreationDate = await _tokenManager.GetCreationDateAsync(token);
                        if (tokenCreationDate.HasValue && (lastActivity == null || tokenCreationDate > lastActivity))
                        {
                            lastActivity = tokenCreationDate;
                        }

                        var tokenExpirationDate = await _tokenManager.GetExpirationDateAsync(token);
                        if (tokenExpirationDate.HasValue && (expiresAt == null || tokenExpirationDate < expiresAt))
                        {
                            expiresAt = tokenExpirationDate;
                        }
                    }
                }
            }

            return new ActiveSessionDto
            {
                Id = id!,
                UserId = subject,
                UserName = user.UserName ?? "Unknown",
                UserEmail = user.Email ?? "Unknown",
                ClientId = clientId!,
                ClientName = clientName!,
                Subject = subject,
                Scopes = scopes.ToList(),
                CreatedAt = creationDate?.DateTime ?? DateTime.UtcNow,
                LastActivity = lastActivity?.DateTime,
                ExpiresAt = expiresAt?.DateTime,
                Status = "Active",
                HasRefreshToken = hasRefreshToken,
                TokenCount = tokenCount,
                IpAddress = "Unknown", // Could be enhanced to track IP
                UserAgent = "Unknown", // Could be enhanced to track User Agent
                SessionType = DetermineSessionType(clientId!)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating session DTO");
            return null;
        }
    }

    /// <summary>
    /// Determines session type based on client ID
    /// </summary>
    private static string DetermineSessionType(string clientId)
    {
        return clientId.ToLowerInvariant() switch
        {
            var id when id.Contains("web") || id.Contains("admin") => "Web",
            var id when id.Contains("mobile") || id.Contains("app") => "Mobile",
            var id when id.Contains("api") || id.Contains("service") || id.Contains("m2m") => "API",
            var id when id.Contains("spa") => "SPA",
            var id when id.Contains("postman") || id.Contains("test") => "Test",
            _ => "Other"
        };
    }
}