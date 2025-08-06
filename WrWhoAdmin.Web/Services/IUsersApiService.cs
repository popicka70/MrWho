using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing users via MrWho API
/// </summary>
public interface IUsersApiService
{
    Task<PagedResult<UserDto>?> GetUsersAsync(int page = 1, int pageSize = 10, string? search = null);
    Task<UserDto?> GetUserAsync(string id);
    Task<UserDto?> CreateUserAsync(CreateUserRequest request);
    Task<UserDto?> UpdateUserAsync(string id, UpdateUserRequest request);
    Task<bool> DeleteUserAsync(string id);
    Task<bool> ResetPasswordAsync(string id, string newPassword);
    Task<bool> ChangePasswordAsync(string id, string currentPassword, string newPassword);
    Task<bool> SetLockoutAsync(string id, DateTimeOffset? lockoutEnd);
    Task<bool> SendConfirmationEmailAsync(string id);
    Task<bool> ForceLogoutAsync(string id);
}