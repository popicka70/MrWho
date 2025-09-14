using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class RealmsApiService : IRealmsApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RealmsApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public RealmsApiService(HttpClient httpClient, ILogger<RealmsApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<PagedResult<RealmDto>?> GetRealmsAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var queryString = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                queryString += $"&search={Uri.EscapeDataString(search)}";
            }

            var response = await _httpClient.GetAsync($"api/realms{queryString}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<PagedResult<RealmDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting realms");
            return null;
        }
    }

    public async Task<RealmDto?> GetRealmAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/realms/{id}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting realm {RealmId}", id);
            return null;
        }
    }

    public async Task<RealmDto?> CreateRealmAsync(CreateRealmRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/realms", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating realm");
            return null;
        }
    }

    public async Task<RealmDto?> UpdateRealmAsync(string id, CreateRealmRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/realms/{id}", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating realm {RealmId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteRealmAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/realms/{id}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting realm {RealmId}", id);
            return false;
        }
    }

    public async Task<RealmDto?> ToggleRealmAsync(string id)
    {
        try
        {
            var response = await _httpClient.PostAsync($"api/realms/{id}/toggle", new StringContent(string.Empty));
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling realm {RealmId}", id);
            return null;
        }
    }

    public async Task<RealmExportDto?> ExportRealmAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/realms/{id}/export");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmExportDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting realm {RealmId}", id);
            return null;
        }
    }

    public async Task<RealmDto?> ImportRealmAsync(RealmExportDto dto)
    {
        try
        {
            var json = JsonSerializer.Serialize(dto, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("api/realms/import", content);
            response.EnsureSuccessStatusCode();
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error importing realm {RealmName}", dto.Name);
            return null;
        }
    }

    public async Task<RealmDto?> UpdateRealmDefaultsAsync(string id, UpdateRealmDefaultsRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PutAsync($"api/realms/{id}/defaults", content);
            response.EnsureSuccessStatusCode();
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RealmDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating realm defaults {RealmId}", id);
            return null;
        }
    }
}
