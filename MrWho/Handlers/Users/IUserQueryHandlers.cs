using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public interface IGetUsersHandler
{
    Task<PagedResult<UserDto>> HandleAsync(int page, int pageSize, string? search);
}

public interface IGetUserHandler
{
    Task<UserDto?> HandleAsync(string id);
}