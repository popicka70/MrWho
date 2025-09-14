using MrWho.Shared;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing client types via MrWho API
/// </summary>
public interface IClientTypesApiService
{
    Task<IEnumerable<ClientTypeInfoDto>?> GetClientTypesAsync();
    Task<ClientTypeInfoDto?> GetClientTypeAsync(ClientType type);
}

/// <summary>
/// Implementation of client types API service
/// </summary>
public class ClientTypesApiService : IClientTypesApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ClientTypesApiService> _logger;

    public ClientTypesApiService(HttpClient httpClient, ILogger<ClientTypesApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<IEnumerable<ClientTypeInfoDto>?> GetClientTypesAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("api/clienttypes");

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<IEnumerable<ClientTypeInfoDto>>();
                _logger.LogInformation("Retrieved {Count} client types", result?.Count() ?? 0);
                return result;
            }
            else
            {
                _logger.LogWarning("Failed to get client types. Status: {StatusCode}", response.StatusCode);
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting client types");
            return null;
        }
    }

    public async Task<ClientTypeInfoDto?> GetClientTypeAsync(ClientType type)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/clienttypes/{type}");

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ClientTypeInfoDto>();
                _logger.LogInformation("Retrieved client type {Type}", type);
                return result;
            }
            else
            {
                _logger.LogWarning("Failed to get client type {Type}. Status: {StatusCode}", type, response.StatusCode);
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting client type {Type}", type);
            return null;
        }
    }
}