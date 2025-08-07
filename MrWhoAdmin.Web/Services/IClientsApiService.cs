using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing clients via MrWho API
/// </summary>
public interface IClientsApiService
{
    Task<PagedResult<ClientDto>?> GetClientsAsync(int page = 1, int pageSize = 10, string? search = null, string? realmId = null);
    Task<ClientDto?> GetClientAsync(string id);
    Task<ClientDto?> CreateClientAsync(CreateClientRequest request);
    Task<ClientDto?> UpdateClientAsync(string id, CreateClientRequest request);
    Task<bool> DeleteClientAsync(string id);
    Task<ClientDto?> ToggleClientAsync(string id);
}