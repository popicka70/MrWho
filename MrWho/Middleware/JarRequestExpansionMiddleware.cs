using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;

namespace MrWho.Middleware;

public class JarRequestExpansionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<JarRequestExpansionMiddleware> _logger;

    public JarRequestExpansionMiddleware(RequestDelegate next, ILogger<JarRequestExpansionMiddleware> logger)
    { _next = next; _logger = logger; }

    private static bool IsAuthorizePath(PathString path)
        => path.HasValue && path.Value!.EndsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase);

    public async Task InvokeAsync(HttpContext context,
        ApplicationDbContext db,
        ISecurityAuditWriter auditWriter)
    {
        var req = context.Request;
        var path = req.Path;

        // Middleware responsibilities reduced (PJ45/PJ46):
        // - No JAR validation/expansion here (handled by OpenIddict extract handler + IJarValidationService)
        // - No response_mode=jwt normalization (handled by event handlers)
        // Remaining: lightweight per-client mode enforcement that depends on handler markers.

        if (HttpMethods.IsGet(req.Method) && IsAuthorizePath(path) && req.Query.ContainsKey(OpenIddictConstants.Parameters.ClientId))
        {
            try
            {
                var clientId = req.Query[OpenIddictConstants.Parameters.ClientId].ToString();
                var client = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
                if (client != null)
                {
                    var jarMode = client.JarMode ?? JarMode.Disabled;
                    var jarmMode = client.JarmMode ?? JarmMode.Disabled;
                    bool jarValidated = req.Query.ContainsKey("_jar_validated");
                    bool jarmRequested = req.Query.ContainsKey("mrwho_jarm");

                    if (jarMode == JarMode.Required && !jarValidated)
                    {
                        await auditWriter.WriteAsync("auth.security", "jar.required_missing", new { clientId }, "warn", actorClientId: clientId);
                        await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequest, "request object required for this client");
                        return;
                    }
                    if (jarmMode == JarmMode.Required && !jarmRequested)
                    {
                        // Event handler will inject; if absent treat as warning (soft) in Phase 1.
                        _logger.LogDebug("JARM Required but mrwho_jarm missing pre-handler for client {ClientId}", clientId);
                    }
                }
            }
            catch (Exception ex)
            { _logger.LogDebug(ex, "Mode enforcement skipped due to error (middleware stub)"); }
        }

        await _next(context);
    }

    private static async Task WriteErrorAsync(HttpContext context, string error, string description)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync($"{{\"error\":\"{error}\",\"error_description\":\"{description}\"}}");
    }
}
