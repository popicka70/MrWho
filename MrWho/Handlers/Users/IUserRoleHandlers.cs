using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public interface IGetUserRolesHandler
{
    Task<List<RoleDto>> HandleAsync(string userId);
}

public interface IAssignRoleHandler
{
    Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(AssignRoleRequest request);
}

public interface IRemoveRoleHandler
{
    Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(RemoveRoleRequest request);
}

public interface IGetRoleUsersHandler
{
    Task<PagedResult<UserDto>> HandleAsync(string roleId, int page, int pageSize, string? search);
}
