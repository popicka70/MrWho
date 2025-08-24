using MrWho.Models;

namespace MrWho.Services;

public enum RoleInclusion
{
    GlobalOnly,
    ClientOnly,
    GlobalAndClient
}

public interface IClientRoleService
{
    Task<IReadOnlyList<string>> GetClientRolesAsync(string userId, string clientId, CancellationToken ct = default);
    Task<IReadOnlyList<string>> GetEffectiveRolesAsync(string userId, string clientId, RoleInclusion inclusion, CancellationToken ct = default);
    Task AddRoleToUserAsync(string userId, string clientId, string roleName, CancellationToken ct = default);
    Task RemoveRoleFromUserAsync(string userId, string clientId, string roleName, CancellationToken ct = default);
}
