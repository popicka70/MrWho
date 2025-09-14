using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public class UsersApiService : IUsersApiService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UsersApiService> _logger;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public UsersApiService(HttpClient httpClient, ILogger<UsersApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<PagedResult<UserDto>?> GetUsersAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var url = $"api/users?page={page}&pageSize={pageSize}" + (string.IsNullOrWhiteSpace(search) ? string.Empty : $"&search={Uri.EscapeDataString(search)}");
            var response = await _httpClient.GetAsync(url);
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
            var response = await _httpClient.GetAsync($"api/users/{Uri.EscapeDataString(id)}");
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
            var response = await _httpClient.GetAsync($"api/users/{Uri.EscapeDataString(id)}/with-claims");
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
            var response = await _httpClient.PutAsync($"api/users/{Uri.EscapeDataString(id)}", content);
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
            var response = await _httpClient.DeleteAsync($"api/users/{Uri.EscapeDataString(id)}");
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
            _logger.LogInformation("Sending confirmation email for user {UserId}", id);
            await Task.Delay(100);
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
            _logger.LogInformation("Forcing logout for user {UserId}", id);
            await Task.Delay(100);
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
            _logger.LogError(ex, "Error adding claim for user {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> RemoveUserClaimAsync(string userId, RemoveUserClaimRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.SendAsync(new HttpRequestMessage
            {
                Method = HttpMethod.Delete,
                RequestUri = new Uri($"api/users/{userId}/claims", UriKind.Relative),
                Content = content
            });

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing claim for user {UserId}", userId);
            return false;
        }
    }

    public async Task<bool> UpdateUserClaimAsync(string userId, string oldClaimType, string oldClaimValue, AddUserClaimRequest newClaim)
    {
        try
        {
            var json = JsonSerializer.Serialize(new { OldClaimType = oldClaimType, OldClaimValue = oldClaimValue, NewClaimType = newClaim.ClaimType, NewClaimValue = newClaim.ClaimValue }, _jsonOptions);
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

    public async Task<List<ClaimTypeInfo>?> GetDistinctClaimTypesAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("api/users/claim-types");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<ClaimTypeInfo>>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting distinct claim types");
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

    public async Task<bool> AssignUserRoleAsync(string userId, AssignRoleRequest request)
    {
        try
        {
            // Defensive: ensure userId is set in request body for model validation
            if (string.IsNullOrWhiteSpace(request.UserId))
            {
                request.UserId = userId;
            }
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"api/users/{userId}/roles", content);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Failed to assign role. Status: {Status}. Body: {Body}", response.StatusCode, body);
            }
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning role for user {UserId}", userId);
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
            _logger.LogError(ex, "Error removing role for user {UserId}", userId);
            return false;
        }
    }

    public async Task<PagedResult<RoleDto>?> GetRolesAsync(int page = 1, int pageSize = 10, string? search = null)
    {
        try
        {
            var url = $"api/users/roles?page={page}&pageSize={pageSize}" + (string.IsNullOrWhiteSpace(search) ? string.Empty : $"&search={Uri.EscapeDataString(search)}");
            var response = await _httpClient.GetAsync(url);
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

    // Profile state
    public async Task<UserProfileStateDto?> GetProfileStateAsync(string userId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"api/users/{userId}/profile-state");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserProfileStateDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting profile state for user {UserId}", userId);
            return null;
        }
    }

    public async Task<bool> SetProfileStateAsync(string userId, SetUserProfileStateRequest request)
    {
        try
        {
            var json = JsonSerializer.Serialize(request, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync($"api/users/{userId}/profile-state", content);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting profile state for user {UserId}", userId);
            return false;
        }
    }

    public async Task<UserEditContextDto?> GetUserEditContextAsync(string userId)
    {
        try
        {
            var resp = await _httpClient.GetAsync($"api/users/{Uri.EscapeDataString(userId)}/edit-context");
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserEditContextDto>(json, _jsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user edit context {UserId}", userId);
            return null;
        }
    }
}
