using MrWho.Shared.Models;

namespace MrWho.Handlers.Roles;

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