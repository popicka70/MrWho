using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing users via MrWho API
/// </summary>
public interface IUsersApiService
{
    Task<PagedResult<UserDto>?> GetUsersAsync(int page = 1, int pageSize = 10, string? search = null);
    Task<UserDto?> GetUserAsync(string id);
    Task<UserWithClaimsDto?> GetUserWithClaimsAsync(string id);
    Task<UserDto?> CreateUserAsync(CreateUserRequest request);
    Task<UserDto?> UpdateUserAsync(string id, UpdateUserRequest request);
    Task<bool> DeleteUserAsync(string id);
    Task<bool> ResetPasswordAsync(string id, string newPassword);
    Task<bool> ChangePasswordAsync(string id, string currentPassword, string newPassword);
    Task<bool> SetLockoutAsync(string id, DateTimeOffset? lockoutEnd);
    Task<bool> SendConfirmationEmailAsync(string id);
    Task<bool> ForceLogoutAsync(string id);
    
    // Claims management
    Task<List<UserClaimDto>?> GetUserClaimsAsync(string userId);
    Task<bool> AddUserClaimAsync(string userId, AddUserClaimRequest request);
    Task<bool> RemoveUserClaimAsync(string userId, RemoveUserClaimRequest request);
    Task<bool> UpdateUserClaimAsync(string userId, string oldClaimType, string oldClaimValue, AddUserClaimRequest newClaim);
    Task<List<ClaimTypeInfo>?> GetDistinctClaimTypesAsync();

    // Role management
    Task<List<RoleDto>?> GetUserRolesAsync(string userId);
    Task<bool> AssignUserRoleAsync(string userId, AssignRoleRequest request);
    Task<bool> RemoveUserRoleAsync(string userId, string roleId);
    Task<PagedResult<RoleDto>?> GetRolesAsync(int page = 1, int pageSize = 10, string? search = null);

    // Profile state
    Task<UserProfileStateDto?> GetProfileStateAsync(string userId);
    Task<bool> SetProfileStateAsync(string userId, SetUserProfileStateRequest request);
    Task<UserEditContextDto?> GetUserEditContextAsync(string userId);
}