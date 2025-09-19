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

                // Only handle /connect/authorize specific preprocessing here.
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
                                dict[kv.Key] = kv.Value.ToString();
                            }

                            // Merge parameters stored at PAR time and keep the embedded JAR so step (2) can validate it.
                            try
                            {
                                var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(par.ParametersJson) ?? new();
                                foreach (var kv in parsed)
                                {
                                    // Prefer existing explicit query values but add missing ones from PAR
                                    if (!dict.ContainsKey(kv.Key) || string.IsNullOrEmpty(dict[kv.Key]))
                                    {
                                        dict[kv.Key] = kv.Value;
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                logger.LogDebug(ex, "[PAR][MW] Failed to parse stored ParametersJson (request_uri={RequestUri})", requestUri);
                            }

                            // Determine whether to keep request_uri param based on client configuration
                            dict["_par_resolved"] = "1";
                            dict["_par_request_uri"] = requestUri;

                            bool keepRequestUri = false;
                            if (dict.TryGetValue(OpenIddictConstants.Parameters.ClientId, out var clientId) && !string.IsNullOrWhiteSpace(clientId))
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
                                    logger.LogDebug(ex, "[PAR][MW] Failed to load client {ClientId} for request_uri retention decision", clientId);
                                }
                            }

                            if (!keepRequestUri)
                            {
                                dict.Remove(OpenIddictConstants.Parameters.RequestUri);
                                logger.LogDebug("[PAR][MW] Stripped request_uri from query (client ParMode != Required)");
                            }
                            else
                            {
                                logger.LogDebug("[PAR][MW] Kept request_uri in query (client ParMode=Required)");
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
                            var originalScope = ctx.Request.Query[OpenIddictConstants.Parameters.Scope].ToString();
                            var parResolved = ctx.Request.Query.ContainsKey("_par_resolved");
                            var result = await validator.ValidateAsync(jwt, queryClientId, ctx.RequestAborted, skipReplayCheck: parResolved);
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
                                // Record both original query scope and JAR scope to enable strict conflict detection later.
                                if (!string.IsNullOrEmpty(originalScope))
                                {
                                    dict["_query_scope"] = originalScope;
                                }
                                if (result.Parameters.TryGetValue(OpenIddictConstants.Parameters.Scope, out var jarScopeVal) && !string.IsNullOrWhiteSpace(jarScopeVal))
                                {
                                    dict["_jar_scope"] = jarScopeVal;
                                }
                                if (result.Parameters.TryGetValue(OpenIddictConstants.Parameters.ResponseMode, out var rmFromJar) && string.Equals(rmFromJar, "jwt", StringComparison.OrdinalIgnoreCase))
                                {
                                    dict.Remove(OpenIddictConstants.Parameters.ResponseMode);
                                    dict["mrwho_jarm"] = "1";
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
