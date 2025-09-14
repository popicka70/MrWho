using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class ApiResourcesApiService : IApiResourcesApiService
{
    private readonly HttpClient _httpClient;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<ApiResourcesApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ApiResourcesApiService(
        HttpClient httpClient,
        IHttpContextAccessor httpContextAccessor,
        ILogger<ApiResourcesApiService> logger)
    {
        _httpClient = httpClient;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true
        };
    }

    public async Task<PagedResult<ApiResourceDto>?> GetApiResourcesAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var queryParams = new List<string>
            {
                $"page={page}",
                $"pageSize={pageSize}"
            };

            if (!string.IsNullOrWhiteSpace(search))
            {
                queryParams.Add($"search={Uri.EscapeDataString(search)}");
            }

            var queryString = string.Join("&", queryParams);
            var response = await _httpClient.GetAsync($"api/apiresources?{queryString}");

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<PagedResult<ApiResourceDto>>(json, _jsonOptions);
            }

            _logger.LogWarning("Failed to get API resources. Status: {StatusCode}, Content: {Content}",
                response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting API resources");
            return null;
        }
    }

    public async Task<ApiResourceDto?> GetApiResourceAsync(string id)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.GetAsync($"api/apiresources/{id}");

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ApiResourceDto>(json, _jsonOptions);
            }

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            _logger.LogWarning("Failed to get API resource {ApiResourceId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting API resource {ApiResourceId}", id);
            return null;
        }
    }

    public async Task<ApiResourceDto?> CreateApiResourceAsync(CreateApiResourceRequest request)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/apiresources", content);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ApiResourceDto>(responseJson, _jsonOptions);
            }

            _logger.LogWarning("Failed to create API resource. Status: {StatusCode}, Content: {Content}",
                response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating API resource");
            return null;
        }
    }

    public async Task<ApiResourceDto?> UpdateApiResourceAsync(string id, UpdateApiResourceRequest request)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/apiresources/{id}", content);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ApiResourceDto>(responseJson, _jsonOptions);
            }

            _logger.LogWarning("Failed to update API resource {ApiResourceId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating API resource {ApiResourceId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteApiResourceAsync(string id)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.DeleteAsync($"api/apiresources/{id}");

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            _logger.LogWarning("Failed to delete API resource {ApiResourceId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting API resource {ApiResourceId}", id);
            return false;
        }
    }

    public async Task<ApiResourceDto?> ToggleApiResourceAsync(string id)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.PostAsync($"api/apiresources/{id}/toggle", null);

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ApiResourceDto>(json, _jsonOptions);
            }

            _logger.LogWarning("Failed to toggle API resource {ApiResourceId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling API resource {ApiResourceId}", id);
            return null;
        }
    }

    private async Task SetAuthorizationHeaderAsync()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext != null)
        {
            var accessToken = await httpContext.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }
        }
    }
}
