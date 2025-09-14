using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class IdentityResourcesApiService : IIdentityResourcesApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<IdentityResourcesApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public IdentityResourcesApiService(HttpClient httpClient, ILogger<IdentityResourcesApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
    }

    public async Task<PagedResult<IdentityResourceDto>> GetIdentityResourcesAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var query = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                query += $"&search={Uri.EscapeDataString(search)}";
            }

            var response = await _httpClient.GetAsync($"api/identityresources{query}");

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get identity resources. Status: {StatusCode}", response.StatusCode);
                throw new HttpRequestException($"Failed to get identity resources: {response.StatusCode}");
            }

            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<PagedResult<IdentityResourceDto>>(json, _jsonOptions);

            return result ?? new PagedResult<IdentityResourceDto>
            {
                Items = new List<IdentityResourceDto>(),
                TotalCount = 0,
                Page = page,
                PageSize = pageSize,
                TotalPages = 0
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting identity resources");
            throw;
        }
    }

    public async Task<IdentityResourceDto?> GetIdentityResourceAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/identityresources/{id}");

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get identity resource {Id}. Status: {StatusCode}", id, response.StatusCode);
                throw new HttpRequestException($"Failed to get identity resource: {response.StatusCode}");
            }

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<IdentityResourceDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting identity resource {Id}", id);
            throw;
        }
    }

    public async Task<IdentityResourceDto?> CreateIdentityResourceAsync(CreateIdentityResourceRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/identityresources", content);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to create identity resource. Status: {StatusCode}, Error: {Error}", response.StatusCode, errorContent);
                return null;
            }

            var responseJson = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<IdentityResourceDto>(responseJson, _jsonOptions);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating identity resource");
            return null;
        }
    }

    public async Task<IdentityResourceDto?> UpdateIdentityResourceAsync(string id, UpdateIdentityResourceRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/identityresources/{id}", content);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to update identity resource {Id}. Status: {StatusCode}, Error: {Error}", id, response.StatusCode, errorContent);
                return null;
            }

            var responseJson = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<IdentityResourceDto>(responseJson, _jsonOptions);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating identity resource {Id}", id);
            return null;
        }
    }

    public async Task DeleteIdentityResourceAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/identityresources/{id}");

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to delete identity resource {Id}. Status: {StatusCode}, Error: {Error}", id, response.StatusCode, errorContent);
                throw new HttpRequestException($"Failed to delete identity resource: {response.StatusCode} - {errorContent}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting identity resource {Id}", id);
            throw;
        }
    }

    public async Task<IdentityResourceDto?> ToggleIdentityResourceAsync(string id)
    {
        try
        {
            var response = await _httpClient.PostAsync($"api/identityresources/{id}/toggle", null);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to toggle identity resource {Id}. Status: {StatusCode}, Error: {Error}", id, response.StatusCode, errorContent);
                return null;
            }

            var responseJson = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<IdentityResourceDto>(responseJson, _jsonOptions);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling identity resource {Id}", id);
            return null;
        }
    }
}
