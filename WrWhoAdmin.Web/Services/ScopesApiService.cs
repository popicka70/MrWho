using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IScopesApiService
{
    Task<PagedResult<ScopeDto>?> GetScopesAsync(int page = 1, int pageSize = 10, string? search = null, ScopeType? type = null);
    Task<ScopeDto?> GetScopeAsync(string id);
    Task<ScopeDto?> CreateScopeAsync(CreateScopeRequest request);
    Task<ScopeDto?> UpdateScopeAsync(string id, UpdateScopeRequest request);
    Task<bool> DeleteScopeAsync(string id);
    Task<ScopeDto?> ToggleScopeAsync(string id);
    Task<List<ScopeDto>?> GetStandardScopesAsync();
}

public class ScopesApiService : IScopesApiService
{
    private readonly HttpClient _httpClient;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<ScopesApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public ScopesApiService(
        HttpClient httpClient,
        IHttpContextAccessor httpContextAccessor,
        ILogger<ScopesApiService> logger)
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

    public async Task<PagedResult<ScopeDto>?> GetScopesAsync(int page = 1, int pageSize = 10, string? search = null, ScopeType? type = null)
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
                queryParams.Add($"search={Uri.EscapeDataString(search)}");

            if (type.HasValue)
                queryParams.Add($"type={type.Value}");

            var queryString = string.Join("&", queryParams);
            var response = await _httpClient.GetAsync($"api/scopes?{queryString}");

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<PagedResult<ScopeDto>>(json, _jsonOptions);
            }

            _logger.LogWarning("Failed to get scopes. Status: {StatusCode}, Content: {Content}",
                response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting scopes");
            return null;
        }
    }

    public async Task<ScopeDto?> GetScopeAsync(string id)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.GetAsync($"api/scopes/{id}");

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ScopeDto>(json, _jsonOptions);
            }

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return null;
            }

            _logger.LogWarning("Failed to get scope {ScopeId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting scope {ScopeId}", id);
            return null;
        }
    }

    public async Task<ScopeDto?> CreateScopeAsync(CreateScopeRequest request)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/scopes", content);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ScopeDto>(responseJson, _jsonOptions);
            }

            _logger.LogWarning("Failed to create scope. Status: {StatusCode}, Content: {Content}",
                response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating scope");
            return null;
        }
    }

    public async Task<ScopeDto?> UpdateScopeAsync(string id, UpdateScopeRequest request)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/scopes/{id}", content);

            if (response.IsSuccessStatusCode)
            {
                var responseJson = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ScopeDto>(responseJson, _jsonOptions);
            }

            _logger.LogWarning("Failed to update scope {ScopeId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating scope {ScopeId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteScopeAsync(string id)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.DeleteAsync($"api/scopes/{id}");

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            _logger.LogWarning("Failed to delete scope {ScopeId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting scope {ScopeId}", id);
            return false;
        }
    }

    public async Task<ScopeDto?> ToggleScopeAsync(string id)
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.PostAsync($"api/scopes/{id}/toggle", null);

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<ScopeDto>(json, _jsonOptions);
            }

            _logger.LogWarning("Failed to toggle scope {ScopeId}. Status: {StatusCode}, Content: {Content}",
                id, response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling scope {ScopeId}", id);
            return null;
        }
    }

    public async Task<List<ScopeDto>?> GetStandardScopesAsync()
    {
        try
        {
            await SetAuthorizationHeaderAsync();

            var response = await _httpClient.GetAsync("api/scopes/standard");

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<List<ScopeDto>>(json, _jsonOptions);
            }

            _logger.LogWarning("Failed to get standard scopes. Status: {StatusCode}, Content: {Content}",
                response.StatusCode, await response.Content.ReadAsStringAsync());
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting standard scopes");
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