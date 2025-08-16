using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IAuditLogsApiService
{
    Task<PagedResult<AuditLogDto>?> GetAuditLogsAsync(int page = 1, int pageSize = 25, string? search = null, string? entityType = null, string? action = null, DateTime? fromUtc = null, DateTime? toUtc = null);
    Task<List<string>> GetEntityTypesAsync();
    Task<List<string>> GetActionsAsync();
}
