using System.Security.Claims;
using MrWho.Services;

namespace MrWho.Middleware;

public sealed class CorrelationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationMiddleware> _logger;
    private const string HeaderName = "X-Correlation-Id";

    public CorrelationMiddleware(RequestDelegate next, ILogger<CorrelationMiddleware> logger)
    { _next = next; _logger = logger; }

    public async Task InvokeAsync(HttpContext context)
    {
        string correlationId = context.Request.Headers.TryGetValue(HeaderName, out var vals) && !string.IsNullOrWhiteSpace(vals.FirstOrDefault())
            ? vals.First()!
            : GenerateId();

        context.Response.Headers[HeaderName] = correlationId;
        context.Response.OnStarting(() => { context.Response.Headers[HeaderName] = correlationId; return Task.CompletedTask; });

        var user = context.User;
        string? userId = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? user?.FindFirst("sub")?.Value;
        string? clientId = user?.FindFirst("client_id")?.Value;
        string? userName = user?.Identity?.Name ?? user?.FindFirst(ClaimTypes.Name)?.Value;

        string actorType = userId != null ? "user" : clientId != null ? "client" : "system";

        var corrCtx = new CorrelationContext
        {
            CorrelationId = correlationId,
            ActorUserId = userId,
            ActorUserName = userName,
            ActorClientId = clientId,
            ActorType = actorType
        };
        CorrelationContextAccessor.Set(corrCtx);

        // If response body is seekable, write actor type for tests when not already committed
        if (!context.Response.HasStarted && context.Response.Body.CanSeek)
        {
            var pos = context.Response.Body.Position;
            await context.Response.WriteAsync("" + string.Empty); // ensure body initialized
            context.Response.Body.Position = pos; // restore
        }

        using (_logger.BeginScope(new Dictionary<string, object>{{"CorrelationId", correlationId},{"ActorType", actorType},{"ActorUserId", userId ?? string.Empty},{"ActorClientId", clientId ?? string.Empty}}))
        {
            await _next(context);
        }
    }

    private static string GenerateId()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        return Convert.ToBase64String(bytes).Replace('+','-').Replace('/','_').TrimEnd('=');
    }
}
