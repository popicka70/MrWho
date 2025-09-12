using System.Security.Claims;
using MrWho.Services;

namespace MrWho.Middleware;

/// <summary>
/// Middleware to ensure every request has a correlation id and resolved actor metadata.
/// </summary>
public sealed class CorrelationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationMiddleware> _logger;
    private const string HeaderName = "X-Correlation-Id";

    public CorrelationMiddleware(RequestDelegate next, ILogger<CorrelationMiddleware> logger)
    { _next = next; _logger = logger; }

    public async Task InvokeAsync(HttpContext context)
    {
        // Correlation Id: accept inbound else create
        string correlationId = context.Request.Headers.TryGetValue(HeaderName, out var vals) && !string.IsNullOrWhiteSpace(vals.FirstOrDefault())
            ? vals.First()!
            : GenerateId();

        // Echo on response
        context.Response.OnStarting(() => { context.Response.Headers[HeaderName] = correlationId; return Task.CompletedTask; });

        // Resolve actor
        var user = context.User;
        string? userId = null; string? userName = null; string? clientId = null; string actorType = "system";
        if (user?.Identity?.IsAuthenticated == true)
        {
            userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? user.FindFirst("sub")?.Value;
            userName = user.Identity?.Name ?? user.FindFirst(ClaimTypes.Name)?.Value;
            clientId = user.FindFirst("client_id")?.Value;
            actorType = userId != null ? "user" : clientId != null ? "client" : "system";
        }

        var ctx = new CorrelationContext
        {
            CorrelationId = correlationId,
            ActorUserId = userId,
            ActorUserName = userName,
            ActorClientId = clientId,
            ActorType = actorType
        };
        CorrelationContextAccessor.Set(ctx);

        using (_logger.BeginScope(new Dictionary<string, object>{{"CorrelationId", correlationId},{"ActorType", actorType},{"ActorUserId", userId ?? string.Empty},{"ActorClientId", clientId ?? string.Empty}}))
        {
            await _next(context);
        }
    }

    private static string GenerateId()
    {
        // 16-char URL safe random id
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        return Convert.ToBase64String(bytes).Replace('+','-').Replace('/','_').TrimEnd('=');
    }
}
