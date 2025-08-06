using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IIdentityResourcesApiService
{
    Task<PagedResult<IdentityResourceDto>> GetIdentityResourcesAsync(int page = 1, int pageSize = 10, string? search = null);
    Task<IdentityResourceDto?> GetIdentityResourceAsync(string id);
    Task<IdentityResourceDto?> CreateIdentityResourceAsync(CreateIdentityResourceRequest request);
    Task<IdentityResourceDto?> UpdateIdentityResourceAsync(string id, UpdateIdentityResourceRequest request);
    Task DeleteIdentityResourceAsync(string id);
    Task<IdentityResourceDto?> ToggleIdentityResourceAsync(string id);
}