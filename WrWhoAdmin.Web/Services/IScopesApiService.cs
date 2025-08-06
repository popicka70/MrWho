using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing scopes via MrWho API
/// </summary>
public interface IScopesApiService
{
    Task<PagedResult<ScopeDto>?> GetScopesAsync(int page = 1, int pageSize = 10, string? search = null, ScopeType? type = null);
    Task<ScopeDto?> GetScopeAsync(string id);
    Task<ScopeDto?> CreateScopeAsync(CreateScopeRequest request);
    Task<ScopeDto?> UpdateScopeAsync(string id, UpdateScopeRequest request);
    Task<bool> DeleteScopeAsync(string id);
    Task<ScopeDto?> ToggleScopeAsync(string id);
    Task<List<ScopeDto>?> GetStandardScopesAsync();
}