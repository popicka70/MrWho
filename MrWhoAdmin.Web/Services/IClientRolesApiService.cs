using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IClientRolesApiService
{
    Task<List<ClientRoleDto>?> GetRolesAsync(string? clientId = null);
    Task<List<string>?> GetUserClientRolesAsync(string clientId, string userId);
    Task<ClientRoleDto?> CreateRoleAsync(CreateClientRoleRequest request);
    Task<bool> DeleteRoleAsync(DeleteClientRoleRequest request);
    Task<bool> AssignRoleAsync(AssignClientRoleRequest request);
    Task<bool> RemoveRoleAsync(RemoveClientRoleRequest request);
}
