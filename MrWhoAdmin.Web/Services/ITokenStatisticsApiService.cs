using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface ITokenStatisticsApiService
{
    Task<TokenStatisticsOverviewDto?> GetOverviewAsync(CancellationToken ct = default);
    Task<List<TokenClientStatDto>> GetTopClientsAsync(int take = 20, CancellationToken ct = default);
    Task<List<TokenTimeSeriesPointDto>> GetTimeSeriesAsync(int days = 14, CancellationToken ct = default);

    // Snapshots
    Task<List<TokenStatisticsSnapshotDto>> GetSnapshotsAsync(string granularity = "daily", int take = 60, CancellationToken ct = default);
    Task<bool> CaptureHourlyAsync(CancellationToken ct = default);
    Task<bool> CaptureDailyAsync(CancellationToken ct = default);
    Task<int> CleanupAsync(int retainDays = 90, CancellationToken ct = default);
}
