using Microsoft.AspNetCore; // for OpenIddict HttpContext extension visibility
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Server.AspNetCore;
using System.Text;

namespace MrWho.Infrastructure;

/// <summary>
/// Lightweight diagnostics for OIDC endpoints. Emits safe, structured logs for PAR/JAR/JARM flows.
/// Enabled when MRWHO_TRACE_OIDC=1 or configuration key OidcTrace:Enabled=true.
/// </summary>
public sealed class OidcTraceMiddleware
{
    private readonly RequestDelegate _next;
    public OidcTraceMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, ILogger<OidcTraceMiddleware> logger, IConfiguration config)
    {
        bool enabled = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TRACE_OIDC"), "1", StringComparison.OrdinalIgnoreCase)
                       || string.Equals(config["OidcTrace:Enabled"], "true", StringComparison.OrdinalIgnoreCase);

        if (!enabled)
        {
            await _next(context);
            return;
        }

        var path = context.Request.Path.Value ?? string.Empty;
        var isOidc = path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase)
                     || path.StartsWith("/.well-known", StringComparison.OrdinalIgnoreCase);
        if (!isOidc)
        {
            await _next(context);
            return;
        }

        // Snapshot basic info
        var method = context.Request.Method;
        var qs = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;
        var hasAuthz = context.Request.Headers.ContainsKey("Authorization");
        var authzPrefix = hasAuthz ? (context.Request.Headers["Authorization"].ToString().Split(' ')[0]) : null;

        // Mask heavy/secret values in query logging
        string Safe(string? key)
        {
            if (string.IsNullOrEmpty(key)) return string.Empty;
            if (string.Equals(key, "client_secret", StringComparison.OrdinalIgnoreCase)) return "***";
            if (string.Equals(key, "request", StringComparison.OrdinalIgnoreCase)) return "<jwt:" + (context.Request.Query[key].ToString().Length) + ">";
            return context.Request.Query[key].ToString();
        }

        try
        {
            var keys = context.Request.Query.Keys.ToArray();
            var kv = string.Join("&", keys.Select(k => k + "=" + Safe(k)));
            logger.LogDebug("[OIDC-TRACE] {Method} {Path} qs=[{Query}] authz={Authz}", method, path, kv, authzPrefix);
        }
        catch { }

        // Try to log OpenIddict parsed request (if available later in pipeline)
        context.Response.OnStarting(async () =>
        {
            try
            {
                var req = context.GetOpenIddictServerRequest();
                if (req is not null)
                {
                    var paramNames = string.Join(',', req.GetParameters().Select(p => p.Key));
                    var hasReq = !string.IsNullOrEmpty(req.Request);
                    var hasReqUri = !string.IsNullOrEmpty(req.RequestUri) || req.GetParameter(OpenIddict.Abstractions.OpenIddictConstants.Parameters.RequestUri) is not null;
                    var hasJarm = string.Equals(req.GetParameter("mrwho_jarm").ToString(), "1", StringComparison.Ordinal) || string.Equals(req.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase);
                    logger.LogDebug("[OIDC-TRACE] parsed params=[{Names}] client_id={ClientId} response_mode={Mode} jar={Jar} par={Par} redirect_uri={Redirect}",
                        paramNames, req.ClientId, req.ResponseMode, hasReq, hasReqUri, req.RedirectUri);
                    if (hasJarm)
                    {
                        logger.LogDebug("[OIDC-TRACE] JARM requested for client={ClientId}", req.ClientId);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "[OIDC-TRACE] Failed to fetch OpenIddictServerRequest");
            }
            await Task.CompletedTask;
        });

        await _next(context);
    }
}
