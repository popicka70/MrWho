using System.Diagnostics;
using System.Security.Claims;

namespace MrWho.Services;

public interface ICorrelationContextAccessor
{
    CorrelationContext Current { get; }
}

public sealed class CorrelationContext
{
    public string CorrelationId { get; init; } = string.Empty;
    public string? ActorUserId { get; init; }
    public string? ActorUserName { get; init; }
    public string? ActorClientId { get; init; }
    public string? ActorType { get; init; } // user|client|system
}

public sealed class CorrelationContextAccessor : ICorrelationContextAccessor // changed to public for test project
{
    private static readonly AsyncLocal<CorrelationContext?> _holder = new();
    public CorrelationContext Current => _holder.Value ?? _empty;
    private static readonly CorrelationContext _empty = new() { CorrelationId = string.Empty, ActorType = "system" };
    internal static void Set(CorrelationContext ctx) => _holder.Value = ctx;
}
