using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public interface ICreateUserHandler
{
    Task<(bool Success, UserDto? User, IEnumerable<string> Errors)> HandleAsync(CreateUserRequest request);
}

public interface IUpdateUserHandler
{
    Task<(bool Success, UserDto? User, IEnumerable<string> Errors)> HandleAsync(string id, UpdateUserRequest request);
}

public interface IDeleteUserHandler
{
    Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id);
}
