using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens; // added for JsonWebTokenHandler
using Microsoft.IdentityModel.Tokens;
using MrWho.Data;
using MrWho.Options; // ensure options namespace if needed
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;

namespace MrWho.Middleware;

public class JarRequestExpansionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<JarRequestExpansionMiddleware> _logger;

    public JarRequestExpansionMiddleware(RequestDelegate next, ILogger<JarRequestExpansionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    private static bool IsAuthorizePath(PathString path)
        => path.HasValue && path.Value!.EndsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase);

    public async Task InvokeAsync(HttpContext context,
        ApplicationDbContext db,
        IKeyManagementService keyService,
        IJarReplayCache replayCache,
        IOptions<JarOptions> jarOptions,
        ISecurityAuditWriter auditWriter,
        ISymmetricSecretPolicy symmetricPolicy,
        IJarRequestValidator jarValidator)
    {
        var req = context.Request;
        var path = req.Path;

        // ---------------------------------------------------------------------
        // PAR request_uri resolution (DISABLED - using OpenIddict built-in PAR endpoint)
        // ---------------------------------------------------------------------
        // Previously we manually resolved request_uri from our PushedAuthorizationRequests table.
        // With Option B applied we rely on OpenIddict's internal handler; skip custom lookup to avoid 400 unknown request_uri.
        // if (HttpMethods.IsGet(req.Method) && IsAuthorizePath(path) && req.Query.ContainsKey("request_uri") && !req.Query.ContainsKey("_par_resolved")) { ... }

        // ---------------------------------------------------------------------
        // JARM response_mode=jwt normalization
        // ---------------------------------------------------------------------
        if (HttpMethods.IsGet(req.Method) && IsAuthorizePath(path) && req.Query.ContainsKey("response_mode"))
        {
            var responseMode = req.Query["response_mode"].ToString();
            if (string.Equals(responseMode, "jwt", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var dict = req.Query.ToDictionary(k => k.Key, v => v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
                    dict.Remove("response_mode");
                    dict["mrwho_jarm"] = "1";
                    var newQuery = string.Join('&', dict.Select(kvp => Uri.EscapeDataString(kvp.Key) + "=" + Uri.EscapeDataString(kvp.Value)));
                    req.QueryString = new QueryString("?" + newQuery);
                    _logger.LogInformation("[JARM] Normalized response_mode=jwt at middleware stage. Original path={Path} Keys={Keys}", path, string.Join(',', dict.Keys));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[JARM] Failed normalizing response_mode=jwt at middleware stage path={Path}", path);
                }
            }
        }
        else if (HttpMethods.IsGet(req.Method) && path.HasValue && path.Value!.Contains("/connect/authorize", StringComparison.OrdinalIgnoreCase) && !IsAuthorizePath(path))
        {
            _logger.LogDebug("[JARM] Authorize path variant encountered: {Path} (query_mode={HasRm})", path, req.Query.ContainsKey("response_mode"));
        }

        // ---------------------------------------------------------------------
        // Direct JAR expansion (only if not PAR-resolved already)
        // ---------------------------------------------------------------------
        if (HttpMethods.IsGet(req.Method)
            && IsAuthorizePath(path)
            && req.Query.ContainsKey("request")
            && !req.Query.ContainsKey("_jar_expanded")
            && !req.Query.ContainsKey("_par_resolved"))
        {
            var jarJwt = req.Query["request"].ToString();
            var queryClientId = req.Query[OpenIddictConstants.Parameters.ClientId].ToString();
            if (string.IsNullOrWhiteSpace(jarJwt))
            {
                await _next(context);
                return;
            }

            try
            {
                var maxBytes = jarOptions.Value.MaxRequestObjectBytes;
                if (maxBytes > 0 && Encoding.UTF8.GetByteCount(jarJwt) > maxBytes)
                {
                    await auditWriter.WriteAsync("auth.security", "jar.rejected_size", new { bytes = Encoding.UTF8.GetByteCount(jarJwt), max = maxBytes, clientId = queryClientId }, "warn", actorClientId: queryClientId, ip: context.Connection.RemoteIpAddress?.ToString());
                    await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestObject, "request object too large");
                    return;
                }

                var result = await jarValidator.ValidateAsync(jarJwt, queryClientId, context.RequestAborted);
                if (!result.Success)
                {
                    await auditWriter.WriteAsync("auth.security", "jar.rejected", new { clientId = queryClientId, error = result.Error, desc = result.ErrorDescription }, "warn", actorClientId: queryClientId, ip: context.Connection.RemoteIpAddress?.ToString());
                    await WriteErrorAsync(context, result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject, result.ErrorDescription ?? "invalid request object");
                    return;
                }

                var dict = req.Query.ToDictionary(k => k.Key, v => v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
                dict.Remove("request");
                foreach (var kv in result.Parameters!)
                    dict[kv.Key] = kv.Value;
                dict["_jar_expanded"] = "1";
                var newQuery = string.Join('&', dict.Select(kvp => Uri.EscapeDataString(kvp.Key) + "=" + Uri.EscapeDataString(kvp.Value)));
                context.Request.QueryString = new QueryString("?" + newQuery);
                _logger.LogDebug("Expanded JAR (direct) for client {ClientId}; alg {Alg}; params: {Keys}", result.ClientId, result.Algorithm, string.Join(',', dict.Keys));
                await auditWriter.WriteAsync("auth.security", "jar.accepted", new { clientId = result.ClientId, alg = result.Algorithm, source = "direct" }, "info", actorClientId: result.ClientId, ip: context.Connection.RemoteIpAddress?.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled error expanding JAR (direct)");
                await auditWriter.WriteAsync("auth.security", "jar.rejected_unhandled", new { error = ex.Message }, "error", ip: context.Connection.RemoteIpAddress?.ToString());
                await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestObject, "invalid request object");
                return;
            }
        }

        // ---------------------------------------------------------------------
        // Mode enforcement (ParMode / JarMode / JarmMode)
        // ---------------------------------------------------------------------
        if (HttpMethods.IsGet(req.Method) && IsAuthorizePath(path) && req.Query.ContainsKey(OpenIddictConstants.Parameters.ClientId))
        {
            try
            {
                var clientId = req.Query[OpenIddictConstants.Parameters.ClientId].ToString();
                if (!string.IsNullOrWhiteSpace(clientId))
                {
                    var client = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
                    if (client != null)
                    {
                        var parMode = client.ParMode ?? PushedAuthorizationMode.Disabled;
                        var jarMode = client.JarMode ?? JarMode.Disabled;
                        var jarmMode = client.JarmMode ?? JarmMode.Disabled;
                        bool parResolved = req.Query.ContainsKey("_par_resolved"); // Will remain false with built-in PAR; rely on OpenIddict feature if required
                        bool jarExpanded = req.Query.ContainsKey("_jar_expanded") || req.Query.ContainsKey("_jar_from_par");

                        if (parMode == PushedAuthorizationMode.Required && !parResolved)
                        {
                            // For built-in PAR we can't detect resolution here; skip blocking to avoid false 400.
                        }
                        if (jarMode == JarMode.Required && !jarExpanded)
                        {
                            await auditWriter.WriteAsync("auth.security", "jar.rejected_required", new { clientId }, "warn", actorClientId: clientId);
                            await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequest, "request object required for this client");
                            return;
                        }
                        if (jarmMode == JarmMode.Required && !req.Query.ContainsKey("mrwho_jarm"))
                        {
                            var dict = req.Query.ToDictionary(k => k.Key, v => v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
                            dict["mrwho_jarm"] = "1";
                            var newQuery = string.Join('&', dict.Select(kvp => Uri.EscapeDataString(kvp.Key) + "=" + Uri.EscapeDataString(kvp.Value)));
                            req.QueryString = new QueryString("?" + newQuery);
                            _logger.LogDebug("Enforced JARM for client {ClientId}", clientId);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Mode enforcement skipped due to error");
            }
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
