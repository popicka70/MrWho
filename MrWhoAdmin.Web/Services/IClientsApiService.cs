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
    Task<ClientDto?> UpdateClientAsync(string id, UpdateClientRequest request);
    Task<bool> DeleteClientAsync(string id);
    Task<ClientDto?> ToggleClientAsync(string id);

    // New export/import
    Task<ClientExportDto?> ExportClientAsync(string id);
    Task<ClientImportResult?> ImportClientAsync(ClientExportDto dto);

    // Identity provider links
    Task<List<ClientIdentityProviderDto>> GetIdentityLinksAsync(string clientId);
    Task<ClientIdentityProviderDto?> AddIdentityLinkAsync(string clientId, string providerId, ClientIdentityProviderDto? dto = null);
    Task<bool> RemoveIdentityLinkAsync(string clientId, string linkId);

    // Secrets
    Task<(bool ok, string? secret)> RotateSecretAsync(string id, string? newSecret = null, DateTime? expiresAtUtc = null, bool retireOld = true);
}
