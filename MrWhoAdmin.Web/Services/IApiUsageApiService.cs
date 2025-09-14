using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IApiUsageApiService
{
    Task<ApiUsageOverviewDto?> GetOverviewAsync(CancellationToken ct = default);
    Task<List<ApiUsageTopClientDto>> GetTopClientsAsync(int take = 20, CancellationToken ct = default);
    Task<List<ApiEndpointUsageDto>> GetTopEndpointsAsync(int take = 20, CancellationToken ct = default);
    Task<List<ApiUsageTimeSeriesPointDto>> GetTimeSeriesAsync(int days = 14, CancellationToken ct = default);
}
