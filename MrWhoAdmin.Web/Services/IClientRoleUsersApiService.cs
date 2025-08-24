namespace MrWhoAdmin.Web.Services;

public interface IClientRoleUsersApiService
{
    Task<List<ClientRoleUserDto>> GetUsersForRoleAsync(string clientId, string roleName);
}

public record ClientRoleUserDto(string Id, string? UserName, string? Email);
