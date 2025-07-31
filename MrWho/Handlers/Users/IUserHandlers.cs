using Microsoft.AspNetCore.Identity;
using MrWho.Models;

namespace MrWho.Handlers.Users;

public interface IGetUsersHandler
{
    Task<PagedResult<UserDto>> HandleAsync(int page, int pageSize, string? search);
}

public interface IGetUserHandler
{
    Task<UserDto?> HandleAsync(string id);
}

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

public interface IChangePasswordHandler
{
    Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id, ChangePasswordRequest request);
}

public interface IResetPasswordHandler
{
    Task<(bool Success, IEnumerable<string> Errors)> HandleAsync(string id, ResetPasswordRequest request);
}

public interface ISetLockoutHandler
{
    Task<(bool Success, string Action, IEnumerable<string> Errors)> HandleAsync(string id, SetLockoutRequest request);
}