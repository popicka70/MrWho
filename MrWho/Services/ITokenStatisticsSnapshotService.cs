using MrWho.Models;

namespace MrWho.Services;

public interface ITokenStatisticsSnapshotService
{
    Task<TokenStatisticsSnapshot> CaptureHourlyAsync(CancellationToken ct = default);
    Task<TokenStatisticsSnapshot> CaptureDailyAsync(CancellationToken ct = default);
    Task<int> CleanupAsync(TimeSpan retainFor, CancellationToken ct = default);
}
