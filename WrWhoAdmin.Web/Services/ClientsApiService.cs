using System.Text;
using System.Text.Json;
using MrWhoAdmin.Web.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing clients via MrWho API
/// </summary>
public interface IClientsApiService
{
    Task<PagedResult<ClientDto>?> GetClientsAsync(int page = 1, int pageSize = 10, string? search = null, string? realmId = null);
    Task<ClientDto?> GetClientAsync(string id);
    Task<ClientDto?> CreateClientAsync(CreateClientRequest request);
    Task<ClientDto?> UpdateClientAsync(string id, CreateClientRequest request);
    Task<bool> DeleteClientAsync(string id);
    Task<ClientDto?> ToggleClientAsync(string id);
}

public class ClientsApiService : IClientsApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ClientsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ClientsApiService(HttpClient httpClient, ILogger<ClientsApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<PagedResult<ClientDto>?> GetClientsAsync(int page = 1, int pageSize = 10, string? search = null, string? realmId = null)
    {
        try
        {
            var queryString = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                queryString += $"&search={Uri.EscapeDataString(search)}";
            }
            if (!string.IsNullOrWhiteSpace(realmId))
            {
                queryString += $"&realmId={Uri.EscapeDataString(realmId)}";
            }

            var response = await _httpClient.GetAsync($"api/clients{queryString}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<PagedResult<ClientDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting clients");
            return null;
        }
    }

    public async Task<ClientDto?> GetClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/clients/{id}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting client {ClientId}", id);
            return null;
        }
    }

    public async Task<ClientDto?> CreateClientAsync(CreateClientRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/clients", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating client");
            return null;
        }
    }

    public async Task<ClientDto?> UpdateClientAsync(string id, CreateClientRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/clients/{id}", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating client {ClientId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/clients/{id}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting client {ClientId}", id);
            return false;
        }
    }

    public async Task<ClientDto?> ToggleClientAsync(string id)
    {
        try
        {
            var response = await _httpClient.PostAsync($"api/clients/{id}/toggle", null);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ClientDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling client {ClientId}", id);
            return null;
        }
    }
}