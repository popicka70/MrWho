using System.Text.Json;
using Microsoft.AspNetCore.Components;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for health check API operations
/// </summary>
public class HealthApiService : IHealthApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<HealthApiService> _logger;
    private readonly NavigationManager _navigationManager;
    private readonly JsonSerializerOptions _jsonOptions;

    public HealthApiService(
        HttpClient httpClient,
        ILogger<HealthApiService> logger,
        NavigationManager navigationManager)
    {
        _httpClient = httpClient;
        _logger = logger;
        _navigationManager = navigationManager;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        // Set base address to current application
        _httpClient.BaseAddress = new Uri(_navigationManager.BaseUri);
    }

    public async Task<HealthStatus?> GetBasicHealthAsync()
    {
        try
        {
            _logger.LogDebug("Fetching basic health status from {BaseAddress}api/health", _httpClient.BaseAddress);
            var response = await _httpClient.GetAsync("api/health");

            _logger.LogDebug("Basic health API response: {StatusCode}", response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                _logger.LogDebug("Basic health API content: {Content}", content);
                var result = JsonSerializer.Deserialize<HealthStatus>(content, _jsonOptions);
                _logger.LogDebug("Successfully retrieved basic health status: {Status}", result?.Status);
                return result;
            }

            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogWarning("Health API returned status code: {StatusCode}, Content: {Content}",
                response.StatusCode, errorContent);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching basic health status");
            return null;
        }
    }

    public async Task<DetailedHealthStatus?> GetDetailedHealthAsync()
    {
        try
        {
            _logger.LogDebug("Fetching detailed health status");
            var response = await _httpClient.GetAsync("api/health/detailed");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<DetailedHealthStatus>(content, _jsonOptions);
                _logger.LogDebug("Successfully retrieved detailed health status with {CheckCount} checks",
                    result?.Checks?.Count ?? 0);
                return result;
            }

            _logger.LogWarning("Detailed health API returned status code: {StatusCode}", response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching detailed health status");
            return null;
        }
    }

    public async Task<LivenessStatus?> GetLivenessAsync()
    {
        try
        {
            _logger.LogDebug("Fetching liveness status");
            var response = await _httpClient.GetAsync("api/health/liveness");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<LivenessStatus>(content, _jsonOptions);
                _logger.LogDebug("Successfully retrieved liveness status: {Status}", result?.Status);
                return result;
            }

            _logger.LogWarning("Liveness API returned status code: {StatusCode}", response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching liveness status");
            return null;
        }
    }

    public async Task<ReadinessStatus?> GetReadinessAsync()
    {
        try
        {
            _logger.LogDebug("Fetching readiness status");
            var response = await _httpClient.GetAsync("api/health/readiness");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<ReadinessStatus>(content, _jsonOptions);
                _logger.LogDebug("Successfully retrieved readiness status: {Status}", result?.Status);
                return result;
            }

            _logger.LogWarning("Readiness API returned status code: {StatusCode}", response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching readiness status");
            return null;
        }
    }

    public async Task<AuthSchemesInfo?> GetAuthSchemesAsync()
    {
        try
        {
            _logger.LogDebug("Fetching authentication schemes information");
            var response = await _httpClient.GetAsync("api/health/auth-schemes");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<AuthSchemesInfo>(content, _jsonOptions);
                _logger.LogDebug("Successfully retrieved auth schemes info for user: {UserName}",
                    result?.User?.Name ?? "Unknown");
                return result;
            }

            _logger.LogWarning("Auth schemes API returned status code: {StatusCode}", response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching authentication schemes information");
            return null;
        }
    }
}