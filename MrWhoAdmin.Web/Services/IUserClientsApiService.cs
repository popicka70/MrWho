using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IUserClientsApiService
{
    Task<UserClientsListDto?> GetClientsForUserAsync(string userIdOrNameOrEmail);
}
