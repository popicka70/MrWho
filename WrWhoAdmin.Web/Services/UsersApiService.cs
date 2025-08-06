using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class UsersApiService : IUsersApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UsersApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions;

    public UsersApiService(HttpClient httpClient, ILogger<UsersApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<PagedResult<UserDto>?> GetUsersAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var queryString = $"?page={page}&pageSize={pageSize}";
            if (!string.IsNullOrWhiteSpace(search))
            {
                queryString += $"&search={Uri.EscapeDataString(search)}";
            }

            var response = await _httpClient.GetAsync($"api/users{queryString}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<PagedResult<UserDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting users");
            return null;
        }
    }

    public async Task<UserDto?> GetUserAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/users/{id}");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user {UserId}", id);
            return null;
        }
    }

    public async Task<UserWithClaimsDto?> GetUserWithClaimsAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/users/{id}/with-claims");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserWithClaimsDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user with claims {UserId}", id);
            return null;
        }
    }

    public async Task<UserDto?> CreateUserAsync(CreateUserRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/users", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating user");
            return null;
        }
    }

    public async Task<UserDto?> UpdateUserAsync(string id, UpdateUserRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/users/{id}", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserDto>(responseJson, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user {UserId}", id);
            return null;
        }
    }

    public async Task<bool> DeleteUserAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/users/{id}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting user {UserId}", id);
            return false;
        }
    }

    public async Task<bool> ResetPasswordAsync(string id, string newPassword)
    {
        try
        {
            var request = new { NewPassword = newPassword };
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"api/users/{id}/reset-password", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for user {UserId}", id);
            return false;
        }
    }

    public async Task<bool> ChangePasswordAsync(string id, string currentPassword, string newPassword)
    {
        try
        {
            var request = new { CurrentPassword = currentPassword, NewPassword = newPassword };
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"api/users/{id}/change-password", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error changing password for user {UserId}", id);
            return false;
        }
    }

    public async Task<bool> SetLockoutAsync(string id, DateTimeOffset? lockoutEnd)
    {
        try
        {
            var request = new { LockoutEnd = lockoutEnd };
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"api/users/{id}/lockout", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting lockout for user {UserId}", id);
            return false;
        }
    }

    public async Task<bool> SendConfirmationEmailAsync(string id)
    {
        try
        {
            // This would typically send a confirmation email
            // For now we'll just return true as a placeholder
            _logger.LogInformation("Sending confirmation email for user {UserId}", id);
            await Task.Delay(100); // Simulate API call
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending confirmation email for user {UserId}", id);
            return false;
        }
    }

    public async Task<bool> ForceLogoutAsync(string id)
    {
        try
        {
            // This would typically invalidate all user sessions
            // For now we'll just return true as a placeholder
            _logger.LogInformation("Forcing logout for user {UserId}", id);
            await Task.Delay(100); // Simulate API call
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error forcing logout for user {UserId}", id);
            return false;
        }
    }

    // Claims management methods
    public async Task<List<UserClaimDto>?> GetUserClaimsAsync(string userId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/users/{userId}/claims");
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<UserClaimDto>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting claims for user {UserId}", userId);
            return null;
        }
    }

    public async Task<bool> AddUserClaimAsync(string userId, AddUserClaimRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"api/users/{userId}/claims", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding claim to user {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> RemoveUserClaimAsync(string userId, RemoveUserClaimRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var requestMessage = new HttpRequestMessage(HttpMethod.Delete, $"api/users/{userId}/claims")
            {
                Content = content
            };

            var response = await _httpClient.SendAsync(requestMessage);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing claim from user {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> UpdateUserClaimAsync(string userId, string oldClaimType, string oldClaimValue, AddUserClaimRequest newClaim)
    {
        try
        {
            var request = new
            {
                OldClaimType = oldClaimType,
                OldClaimValue = oldClaimValue,
                NewClaimType = newClaim.ClaimType,
                NewClaimValue = newClaim.ClaimValue
            };

            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PutAsync($"api/users/{userId}/claims", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating claim for user {UserId}", userId);
            return false;
        }
    }

    // Role management methods  
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

    public async Task<bool> AssignUserRoleAsync(string userId, AssignRoleRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"api/users/{userId}/roles", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning role to user {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> RemoveUserRoleAsync(string userId, string roleId)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"api/users/{userId}/roles/{roleId}");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing role from user {UserId}", userId);
            return false;
        }
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

            var response = await _httpClient.GetAsync($"api/users/roles{queryString}");
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
}