using Microsoft.AspNetCore.Http;

namespace MrWho.Services;

public interface ICorrelationContextAccessor
{
    CorrelationContext Current { get; }
    // Internal use: middleware sets the context
    void Set(CorrelationContext context);
}

public sealed class CorrelationContext
{
    public string CorrelationId { get; init; } = string.Empty;
    public string? ActorUserId { get; init; }
    public string? ActorUserName { get; init; }
    public string? ActorClientId { get; init; }
    public string? ActorType { get; init; } // user|client|system
}

public sealed class CorrelationContextAccessor : ICorrelationContextAccessor
{
    private readonly IHttpContextAccessor _http;
    private const string ItemKey = "__CorrelationContext";
    private static readonly CorrelationContext _empty = new() { CorrelationId = string.Empty, ActorType = "system" };

    public CorrelationContextAccessor(IHttpContextAccessor http) => _http = http;

    public CorrelationContext Current
    {
        get
        {
            var http = _http.HttpContext;
            if (http == null)
            {
                return _empty;
            }

            if (http.Items.TryGetValue(ItemKey, out var value) && value is CorrelationContext ctx)
            {
                return ctx;
            }

            return _empty;
        }
    }

    public void Set(CorrelationContext context)
    {
        var http = _http.HttpContext;
        if (http != null)
        {
            http.Items[ItemKey] = context;
        }
    }
}
