using MrWho.Models;

namespace MrWho.Services;

public interface IReturnUrlStore
{
    Task<string> SaveAsync(string url, string? clientId = null, TimeSpan? ttl = null, CancellationToken ct = default);
    Task<string?> ResolveAsync(string id, CancellationToken ct = default);
    Task<int> CleanupExpiredAsync(CancellationToken ct = default);
}
