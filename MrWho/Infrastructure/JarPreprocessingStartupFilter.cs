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
using MrWho.Shared; // for PushedAuthorizationMode

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

                // Strip any Authorization-like artifacts for ALL /connect endpoints to avoid OpenIddict validation from engaging.
                if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method)) &&
                    ctx.Request.Path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase))
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
                                // Copy current query as baseline; we'll conditionally keep/remove request_uri below.
                                dict[kv.Key] = kv.Value.ToString();
                            }

                            // Merge parameters stored at PAR time without re-validating the embedded JAR
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

                            // Conditionally keep or strip request_uri based on client configuration
                            bool keepRequestUri = false;
                            string? clientId = null;
                            dict.TryGetValue(OpenIddictConstants.Parameters.ClientId, out clientId);
                            if (!string.IsNullOrWhiteSpace(clientId))
                            {
                                try
                                {
                                    var client = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId, ctx.RequestAborted);
                                    if (client != null)
                                    {
                                        keepRequestUri = (client.ParMode ?? PushedAuthorizationMode.Disabled) == PushedAuthorizationMode.Required;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    logger.LogDebug(ex, "[PAR][MW] Failed to load client {ClientId} for request_uri handling", clientId);
                                }
                            }

                            if (!keepRequestUri)
                            {
                                dict.Remove(OpenIddictConstants.Parameters.RequestUri);
                                logger.LogDebug("[PAR][MW] Stripped request_uri from query for client {ClientId} (PAR not required)", clientId ?? "?");
                            }
                            else
                            {
                                logger.LogDebug("[PAR][MW] Kept request_uri for client {ClientId} (PAR required)", clientId ?? "?");
                            }

                            ctx.Request.QueryString = QueryString.Create(dict!);
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

                    // 3) JARM response_mode normalization: strip explicit response_mode=jwt and inject flag marker
                    if (ctx.Request.Query.TryGetValue(OpenIddictConstants.Parameters.ResponseMode, out var rm) && string.Equals(rm.ToString(), "jwt", StringComparison.OrdinalIgnoreCase))
                    {
                        var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                        foreach (var kv in ctx.Request.Query)
                        {
                            if (string.Equals(kv.Key, OpenIddictConstants.Parameters.ResponseMode, StringComparison.OrdinalIgnoreCase))
                            {
                                continue; // remove response_mode from front-channel
                            }
                            dict[kv.Key] = kv.Value.ToString();
                        }
                        dict["mrwho_jarm"] = "1"; // signal JARM for downstream handlers
                        ctx.Request.QueryString = QueryString.Create(dict!);
                        logger.LogDebug("[JARM][MW] Normalized response_mode=jwt -> injected mrwho_jarm=1 and removed response_mode from query");
                    }
                }
                await nxt();
            });
            next(app);
        };    }
}
