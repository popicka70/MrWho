using MrWho.Models;

namespace MrWho.Services;

/// <summary>
/// Service for managing dynamic OIDC client configurations
/// </summary>
public interface IOidcClientService
{
    Task InitializeEssentialDataAsync();
    Task InitializeDefaultRealmAndClientsAsync();
    Task<IEnumerable<Client>> GetEnabledClientsAsync();
    Task SyncClientWithOpenIddictAsync(Client client);
}
