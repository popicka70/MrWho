using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MrWho.Services;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Primitives;
using MrWho.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace MrWho.Infrastructure;

public sealed class JarPreprocessingStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.Use(async (ctx, nxt) =>
            {
                var logger = ctx.RequestServices.GetRequiredService<ILogger<JarPreprocessingStartupFilter>>();

                // Only strip Authorization for /connect/authorize to prevent validation middleware from intercepting authorize
                if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method)) &&
                    ctx.Request.Path.StartsWithSegments("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    if (ctx.Request.Headers.ContainsKey("Authorization"))
                    {
                        logger.LogDebug("[AUTHZ-MW] Stripping Authorization header for {Path}", ctx.Request.Path);
                        ctx.Request.Headers.Remove("Authorization");
                    }
                }

                if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method)) && ctx.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    // 1) PAR request_uri pre-resolution
                    if (ctx.Request.Query.TryGetValue(OpenIddictConstants.Parameters.RequestUri, out var requestUriValues) && !StringValues.IsNullOrEmpty(requestUriValues))
                    {
                        try
                        {
                            var requestUri = requestUriValues.ToString();
                            var db = ctx.RequestServices.GetRequiredService<ApplicationDbContext>();
                            var par = await db.PushedAuthorizationRequests.AsNoTracking().FirstOrDefaultAsync(p => p.RequestUri == requestUri, ctx.RequestAborted);
                            if (par == null)
                            {
                                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await ctx.Response.WriteAsJsonAsync(new
                                {
                                    error = OpenIddictConstants.Errors.InvalidRequestUri,
                                    error_description = "unknown request_uri"
                                });
                                return;
                            }

                            var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                            foreach (var kv in ctx.Request.Query)
                            {
                                // We'll drop request_uri after merge to avoid double processing by downstream components.
                                if (string.Equals(kv.Key, OpenIddictConstants.Parameters.RequestUri, StringComparison.OrdinalIgnoreCase))
                                {
                                    continue;
                                }
                                dict[kv.Key] = kv.Value.ToString();
                            }

                            try
                            {
                                var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(par.ParametersJson) ?? new();
                                foreach (var kv in parsed)
                                {
                                    // Do NOT re-inject the raw request object from PAR into front-channel
                                    if (string.Equals(kv.Key, OpenIddictConstants.Parameters.Request, StringComparison.OrdinalIgnoreCase))
                                    {
                                        continue;
                                    }
                                    if (!dict.ContainsKey(kv.Key))
                                    {
                                        dict[kv.Key] = kv.Value;
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                logger.LogDebug(ex, "[PAR][MW] Failed to parse stored ParametersJson (request_uri={RequestUri})", requestUri);
                            }

                            dict["_par_resolved"] = "1";
                            ctx.Request.QueryString = QueryString.Create(dict!);
                            logger.LogDebug("[PAR][MW] Pre-resolved request_uri, merged params and removed request_uri from query");
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "[PAR][MW] request_uri preprocessing failed");
                            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                            await ctx.Response.WriteAsJsonAsync(new { error = OpenIddictConstants.Errors.InvalidRequestUri, error_description = "invalid request_uri" });
                            return;
                        }
                    }

                    // 2) JAR 'request' pre-processing (strip after validation)
                    if (ctx.Request.Query.TryGetValue(OpenIddictConstants.Parameters.Request, out var raw) && !StringValues.IsNullOrEmpty(raw))
                    {
                        try
                        {
                            var validator = ctx.RequestServices.GetRequiredService<IJarValidationService>();
                            var jwt = raw.ToString();
                            var queryClientId = ctx.Request.Query[OpenIddictConstants.Parameters.ClientId].ToString();
                            var originalRedirect = ctx.Request.Query[OpenIddictConstants.Parameters.RedirectUri].ToString();
                            var result = await validator.ValidateAsync(jwt, queryClientId, ctx.RequestAborted);
                            if (result.Success && result.Parameters != null)
                            {
                                var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                                foreach (var kv in ctx.Request.Query)
                                {
                                    if (string.Equals(kv.Key, OpenIddictConstants.Parameters.Request, StringComparison.OrdinalIgnoreCase)) continue; // strip
                                    dict[kv.Key] = kv.Value.ToString();
                                }
                                foreach (var kv in result.Parameters)
                                {
                                    if (string.Equals(kv.Key, OpenIddictConstants.Parameters.Request, StringComparison.OrdinalIgnoreCase)) continue;
                                    if (!dict.ContainsKey(kv.Key))
                                    {
                                        dict[kv.Key] = kv.Value;
                                    }
                                }
                                if (!dict.ContainsKey(OpenIddictConstants.Parameters.RedirectUri) || string.IsNullOrEmpty(dict[OpenIddictConstants.Parameters.RedirectUri]))
                                {
                                    if (!string.IsNullOrEmpty(originalRedirect))
                                    {
                                        dict[OpenIddictConstants.Parameters.RedirectUri] = originalRedirect;
                                    }
                                }
                                dict["_jar_validated"] = "1";
                                ctx.Request.QueryString = QueryString.Create(dict!);
                                logger.LogDebug("[JAR][MW] Preprocessed request object (client {ClientId}, merged {Count} params)", result.ClientId, result.Parameters.Count);
                            }
                            else
                            {
                                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await ctx.Response.WriteAsJsonAsync(new
                                {
                                    error = result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject,
                                    error_description = result.ErrorDescription ?? "invalid request object"
                                });
                                return;
                            }
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "[JAR][MW] Middleware preprocessing failed");
                            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                            await ctx.Response.WriteAsJsonAsync(new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "invalid request object" });
                            return;
                        }
                    }

                    // 3) JARM response_mode normalization: if response_mode=jwt was explicitly supplied, remove it
                    // and inject a lightweight marker that we requested JARM. The server will honor JARM mode later.
                    if (ctx.Request.Query.TryGetValue(OpenIddictConstants.Parameters.ResponseMode, out var rm) &&
                        string.Equals(rm.ToString(), "jwt", StringComparison.OrdinalIgnoreCase))
                    {
                        var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                        foreach (var kv in ctx.Request.Query)
                        {
                            if (string.Equals(kv.Key, OpenIddictConstants.Parameters.ResponseMode, StringComparison.OrdinalIgnoreCase))
                            {
                                continue; // strip response_mode from front-channel
                            }
                            dict[kv.Key] = kv.Value.ToString();
                        }
                        // Inject a flag so downstream login redirect (returnUrl) carries an indicator
                        dict["mrwho_jarm"] = "1";
                        ctx.Request.QueryString = QueryString.Create(dict!);
                        logger.LogDebug("[JARM][MW] Normalized response_mode=jwt -> injected mrwho_jarm=1 and removed response_mode from query");
                    }
                }
                await nxt();
            });
            next(app);
        };    }
}
