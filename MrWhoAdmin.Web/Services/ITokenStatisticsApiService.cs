using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface ITokenStatisticsApiService
{
    Task<TokenStatisticsOverviewDto?> GetOverviewAsync(CancellationToken ct = default);
    Task<List<TokenClientStatDto>> GetTopClientsAsync(int take = 20, CancellationToken ct = default);
    Task<List<TokenTimeSeriesPointDto>> GetTimeSeriesAsync(int days = 14, CancellationToken ct = default);
}
