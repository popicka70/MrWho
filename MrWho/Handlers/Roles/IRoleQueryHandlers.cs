using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public interface IGetRolesHandler
{
    Task<PagedResult<RoleDto>> HandleAsync(int page, int pageSize, string? search);
}

public interface IGetRoleHandler
{
    Task<RoleDto?> HandleAsync(string id);
}