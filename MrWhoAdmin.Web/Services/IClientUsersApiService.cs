using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IClientUsersApiService
{
    Task<ClientUsersListDto?> GetClientUsersAsync(string clientIdOrPublicId);
    Task<ClientUserDto?> AssignUserAsync(string clientIdOrPublicId, AssignClientUserRequest request);
    Task<bool> RemoveUserAsync(string clientIdOrPublicId, string userId);
}
