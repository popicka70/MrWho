using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for managing realms via MrWho API
/// </summary>
public interface IRealmsApiService
{
    Task<PagedResult<RealmDto>?> GetRealmsAsync(int page = 1, int pageSize = 10, string? search = null);
    Task<RealmDto?> GetRealmAsync(string id);
    Task<RealmDto?> CreateRealmAsync(CreateRealmRequest request);
    Task<RealmDto?> UpdateRealmAsync(string id, CreateRealmRequest request);
    Task<bool> DeleteRealmAsync(string id);
    Task<RealmDto?> ToggleRealmAsync(string id);

    // New export/import
    Task<RealmExportDto?> ExportRealmAsync(string id);
    Task<RealmDto?> ImportRealmAsync(RealmExportDto dto);
}