using MrWho.Models;

namespace MrWho.Handlers.Users;

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