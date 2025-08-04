using Microsoft.AspNetCore.Identity;
using MrWho.Models;
using MrWho.Shared.Models;

namespace MrWho.Handlers.Roles;

// Role management interfaces
public interface IGetRolesHandler
{
    Task<PagedResult<RoleDto>> HandleAsync(int page, int pageSize, string? search);
}

public interface IGetRoleHandler
{
    Task<RoleDto?> HandleAsync(string id);
}

public interface ICreateRoleHandler
{
    Task<(bool Success, RoleDto? Role, IEnumerable<string> Errors)> HandleAsync(CreateRoleRequest request);
}

public interface IUpdateRoleHandler
{
    Task<(bool Success, RoleDto? Role, IEnumerable<string> Errors)> HandleAsync(string id, UpdateRoleRequest request);
}

public interface IDeleteRoleHandler
{
    Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id);
}

// User-Role assignment interfaces
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