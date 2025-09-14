using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing roles via MrWho API
/// </summary>
public interface IRolesApiService
{
    Task<PagedResult<RoleDto>?> GetRolesAsync(int page = 1, int pageSize = 10, string? search = null);
    Task<RoleDto?> GetRoleAsync(string id);
    Task<RoleDto?> CreateRoleAsync(CreateRoleRequest request);
    Task<RoleDto?> UpdateRoleAsync(string id, UpdateRoleRequest request);
    Task<bool> DeleteRoleAsync(string id);
    Task<PagedResult<UserDto>?> GetRoleUsersAsync(string roleId, int page = 1, int pageSize = 10, string? search = null);
    Task<List<RoleDto>?> GetUserRolesAsync(string userId);
    Task<bool> AssignRoleAsync(string userId, string roleId);
    Task<bool> RemoveRoleAsync(string userId, string roleId);
}

public class RolesApiService : IRolesApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<RolesApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public RolesApiService(HttpClient httpClient, ILogger<RolesApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<PagedResult<RoleDto>?> GetRolesAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var queryString = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                queryString += $"&search={Uri.EscapeDataString(search)}";
            }

            var response = await _httpClient.GetAsync($"api/roles{queryString}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<PagedResult<RoleDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting roles");
            return null;
        }
    }

    public async Task<RoleDto?> GetRoleAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/roles/{id}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RoleDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting role {RoleId}", id);
            return null;
        }
    }

    public async Task<RoleDto?> CreateRoleAsync(CreateRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/roles", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RoleDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating role");
            return null;
        }
    }

    public async Task<RoleDto?> UpdateRoleAsync(string id, UpdateRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/roles/{id}", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RoleDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating role {RoleId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteRoleAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/roles/{id}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting role {RoleId}", id);
            return false;
        }
    }

    public async Task<PagedResult<UserDto>?> GetRoleUsersAsync(string roleId, int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var queryString = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                queryString += $"&search={Uri.EscapeDataString(search)}";
            }

            var response = await _httpClient.GetAsync($"api/roles/{roleId}/users{queryString}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<PagedResult<UserDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting users for role {RoleId}", roleId);
            return null;
        }
    }

    public async Task<List<RoleDto>?> GetUserRolesAsync(string userId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/users/{userId}/roles");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<RoleDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting roles for user {UserId}", userId);
            return null;
        }
    }

    public async Task<bool> AssignRoleAsync(string userId, string roleId)
    {
        try
        {
            var request = new { UserId = userId, RoleId = roleId };
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/roles/assign", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning role {RoleId} to user {UserId}", roleId, userId);
            return false;
        }
    }

    public async Task<bool> RemoveRoleAsync(string userId, string roleId)
    {
        try
        {
            var request = new { UserId = userId, RoleId = roleId };
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/roles/remove", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing role {RoleId} from user {UserId}", roleId, userId);
            return false;
        }
    }
}
