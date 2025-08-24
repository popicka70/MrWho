namespace MrWho.Services;

/// <summary>
/// Explicit initializer that registers all dynamic client/realm cookie authentication schemes.
/// Called at startup (before first request) to avoid race with authorization policy evaluation.
/// Safe to call multiple times (idempotent).
/// </summary>
public interface IDynamicClientCookieRegistrar
{
    Task RegisterAllAsync(CancellationToken cancellationToken = default);
}
