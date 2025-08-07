using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing API resources via MrWho API
/// </summary>
public interface IApiResourcesApiService
{
    Task<PagedResult<ApiResourceDto>?> GetApiResourcesAsync(int page = 1, int pageSize = 10, string? search = null);
    Task<ApiResourceDto?> GetApiResourceAsync(string id);
    Task<ApiResourceDto?> CreateApiResourceAsync(CreateApiResourceRequest request);
    Task<ApiResourceDto?> UpdateApiResourceAsync(string id, UpdateApiResourceRequest request);
    Task<bool> DeleteApiResourceAsync(string id);
    Task<ApiResourceDto?> ToggleApiResourceAsync(string id);
}