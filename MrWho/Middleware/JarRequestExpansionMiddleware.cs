using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MrWho.Data;
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens; // added for JsonWebTokenHandler
using MrWho.Options; // ensure options namespace if needed

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
        IKeyManagementService keyService, // retained (may be used by later tasks)
        IJarReplayCache replayCache, // retained
        IOptions<JarOptions> jarOptions,
        ISecurityAuditWriter auditWriter,
        ISymmetricSecretPolicy symmetricPolicy, // retained
        IJarRequestValidator jarValidator)
    {
        var req = context.Request;
        var path = req.Path;

        // ---------------------------------------------------------------------
        // PAR request_uri resolution (must run before JARM normalization/JAR expansion)
        // ---------------------------------------------------------------------
        if (HttpMethods.IsGet(req.Method) && IsAuthorizePath(path) && req.Query.ContainsKey("request_uri") && !req.Query.ContainsKey("_par_resolved"))
        {
            var requestUri = req.Query["request_uri"].ToString();
            try
            {
                if (!string.IsNullOrWhiteSpace(requestUri) && requestUri.StartsWith("urn:ietf:params:oauth:request_uri:", StringComparison.OrdinalIgnoreCase))
                {
                    var par = await db.PushedAuthorizationRequests.FirstOrDefaultAsync(p => p.RequestUri == requestUri);
                    if (par == null)
                    {
                        await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestUri, "unknown request_uri");
                        return;
                    }
                    if (par.ExpiresAt < DateTime.UtcNow)
                    {
                        await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestUri, "expired request_uri");
                        return;
                    }
                    if (par.ConsumedAt != null)
                    {
                        await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestUri, "request_uri already used");
                        return;
                    }

                    // Mark consumed
                    par.ConsumedAt = DateTime.UtcNow;
                    await db.SaveChangesAsync();

                    // Deserialize stored parameters JSON
                    string? jarJwt = null;
                    Dictionary<string,string>? storedParams = null;
                    try
                    {
                        using var doc = JsonDocument.Parse(par.ParametersJson);
                        var root = doc.RootElement;
                        if (root.TryGetProperty("parameters", out var pElem) && pElem.ValueKind == JsonValueKind.Object)
                        {
                            storedParams = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                            foreach (var prop in pElem.EnumerateObject())
                            {
                                storedParams[prop.Name] = prop.Value.GetString() ?? string.Empty;
                            }
                        }
                        if (root.TryGetProperty("jar", out var jarElem) && jarElem.ValueKind == JsonValueKind.String)
                        {
                            jarJwt = jarElem.GetString();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed parsing stored PAR parameters for {RequestUri}", requestUri);
                        await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestUri, "invalid stored parameters");
                        return;
                    }

                    if (storedParams == null)
                    {
                        await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestUri, "missing stored parameters");
                        return;
                    }

                    // Rebuild query: remove request_uri, inject stored parameters. We trust prior validation.
                    var merged = req.Query.ToDictionary(k => k.Key, v => v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
                    merged.Remove("request_uri");
                    merged.Remove("request"); // ensure no leftover direct request
                    foreach (var kv in storedParams)
                        merged[kv.Key] = kv.Value;
                    merged["_par_resolved"] = "1";
                    if (jarJwt != null) merged["_jar_from_par"] = "1";
                    var newQuery = string.Join('&', merged.Select(kvp => Uri.EscapeDataString(kvp.Key) + "=" + Uri.EscapeDataString(kvp.Value)));
                    req.QueryString = new QueryString("?" + newQuery);
                    _logger.LogDebug("Resolved PAR request_uri for client {ClientId} keys={Keys}", storedParams.GetValueOrDefault(OpenIddictConstants.Parameters.ClientId), string.Join(',', merged.Keys));
                    await auditWriter.WriteAsync("auth.security", "par.resolved", new { requestUri, clientId = storedParams.GetValueOrDefault(OpenIddictConstants.Parameters.ClientId) }, "info", actorClientId: storedParams.GetValueOrDefault(OpenIddictConstants.Parameters.ClientId));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled PAR resolution error for {RequestUri}", requestUri);
                await WriteErrorAsync(context, OpenIddictConstants.Errors.InvalidRequestUri, "request_uri resolution error");
                return;
            }
        }

        // ---------------------------------------------------------------------
        // JARM response_mode=jwt normalization (run before OpenIddict extraction)
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
                    dict["mrwho_jarm"] = "1"; // custom flag consumed by JARM handlers
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
        // Direct JAR expansion (only if not resolved via PAR already)
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

        await _next(context);
    }

    private static async Task WriteErrorAsync(HttpContext context, string error, string description)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync($"{{\"error\":\"{error}\",\"error_description\":\"{description}\"}}");
    }
}
