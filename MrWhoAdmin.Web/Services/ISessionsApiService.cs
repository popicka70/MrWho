using MrWho.Shared;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing and monitoring active user sessions
/// </summary>
public interface ISessionsApiService
{
    /// <summary>
    /// Gets all active sessions across all clients
    /// </summary>
    Task<List<ActiveSessionDto>?> GetActiveSessionsAsync();

    /// <summary>
    /// Gets active sessions for a specific user
    /// </summary>
    Task<List<ActiveSessionDto>?> GetUserActiveSessionsAsync(string userId);

    /// <summary>
    /// Gets active sessions for a specific client
    /// </summary>
    Task<List<ActiveSessionDto>?> GetClientActiveSessionsAsync(string clientId);

    /// <summary>
    /// Revokes a specific session (authorization and all related tokens)
    /// </summary>
    Task<bool> RevokeSessionAsync(string authorizationId);

    /// <summary>
    /// Revokes all sessions for a specific user
    /// </summary>
    Task<bool> RevokeAllUserSessionsAsync(string userId);

    /// <summary>
    /// Revokes all sessions for a specific client
    /// </summary>
    Task<bool> RevokeAllClientSessionsAsync(string clientId);

    /// <summary>
    /// Gets session statistics
    /// </summary>
    Task<SessionStatisticsDto?> GetSessionStatisticsAsync();
}
