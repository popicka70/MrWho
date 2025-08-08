using System.Text.Json;
using System.Text;
using MrWho.Shared;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// API service for managing and monitoring active user sessions
/// </summary>
public class SessionsApiService : ISessionsApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<SessionsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public SessionsApiService(HttpClient httpClient, ILogger<SessionsApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<List<ActiveSessionDto>?> GetActiveSessionsAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("api/sessions/active");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ActiveSessionDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active sessions");
            return null;
        }
    }

    public async Task<List<ActiveSessionDto>?> GetUserActiveSessionsAsync(string userId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/sessions/user/{userId}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ActiveSessionDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active sessions for user {UserId}", userId);
            return null;
        }
    }

    public async Task<List<ActiveSessionDto>?> GetClientActiveSessionsAsync(string clientId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/sessions/client/{clientId}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ActiveSessionDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active sessions for client {ClientId}", clientId);
            return null;
        }
    }

    public async Task<bool> RevokeSessionAsync(string authorizationId)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/sessions/{authorizationId}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking session {AuthorizationId}", authorizationId);
            return false;
        }
    }

    public async Task<bool> RevokeAllUserSessionsAsync(string userId)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/sessions/user/{userId}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking all sessions for user {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> RevokeAllClientSessionsAsync(string clientId)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/sessions/client/{clientId}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking all sessions for client {ClientId}", clientId);
            return false;
        }
    }

    public async Task<SessionStatisticsDto?> GetSessionStatisticsAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("api/sessions/statistics");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<SessionStatisticsDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting session statistics");
            return null;
        }
    }
}