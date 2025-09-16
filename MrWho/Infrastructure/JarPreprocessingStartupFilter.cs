using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MrWho.Options;
using MrWho.Services;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace MrWho.Infrastructure;

/// <summary>
/// Early middleware that intercepts /connect/authorize requests and processes the 'request' parameter
/// BEFORE OpenIddict's built-in extraction/validation so we can support JAR without patching OpenIddict.
/// It validates, merges parameters and strips the original 'request' parameter so core handlers don't reject it (ID2028).
/// This runs very early in the pipeline.
/// </summary>
public sealed class JarPreprocessingStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.Use(async (ctx, nxt) =>
            {
                if (HttpMethods.IsGet(ctx.Request.Method) && ctx.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    // Only run if 'request' query parameter present
                    if (ctx.Request.Query.TryGetValue(OpenIddictConstants.Parameters.Request, out var raw) && !StringValues.IsNullOrEmpty(raw))
                    {
                        var logger = ctx.RequestServices.GetRequiredService<ILogger<JarPreprocessingStartupFilter>>();
                        try
                        {
                            var validator = ctx.RequestServices.GetRequiredService<IJarValidationService>();
                            var adv = ctx.RequestServices.GetRequiredService<IOptions<OidcAdvancedOptions>>().Value;
                            var jwt = raw.ToString();
                            var queryClientId = ctx.Request.Query[OpenIddictConstants.Parameters.ClientId].ToString();
                            var originalRedirect = ctx.Request.Query[OpenIddictConstants.Parameters.RedirectUri].ToString();
                            var result = await validator.ValidateAsync(jwt, queryClientId, ctx.RequestAborted);
                            if (result.Success && result.Parameters != null)
                            {
                                // Reconstruct query collection with merged params sans 'request'
                                var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                                foreach (var kv in ctx.Request.Query)
                                {
                                    if (string.Equals(kv.Key, OpenIddictConstants.Parameters.Request, StringComparison.OrdinalIgnoreCase)) continue; // strip
                                    dict[kv.Key] = kv.Value.ToString();
                                }
                                // Merge JAR parameters (they take precedence only if not already present to honor query/JAR conflict policy)
                                foreach (var kv in result.Parameters)
                                {
                                    if (string.Equals(kv.Key, OpenIddictConstants.Parameters.Request, StringComparison.OrdinalIgnoreCase)) continue; // never re-add
                                    if (!dict.ContainsKey(kv.Key))
                                    {
                                        dict[kv.Key] = kv.Value;
                                    }
                                }
                                // Ensure redirect_uri present (fallback to original query if JAR omitted)
                                if (!dict.ContainsKey(OpenIddictConstants.Parameters.RedirectUri) || string.IsNullOrEmpty(dict[OpenIddictConstants.Parameters.RedirectUri]))
                                {
                                    if (!string.IsNullOrEmpty(originalRedirect))
                                    {
                                        dict[OpenIddictConstants.Parameters.RedirectUri] = originalRedirect;
                                    }
                                }
                                dict["_jar_validated"] = "1";
                                ctx.Request.QueryString = QueryString.Create(dict!);
                                logger.LogDebug("[JAR][MW] Preprocessed request object (client {ClientId}, merged {Count} params, redirect_uri={RedirectUri})", result.ClientId, result.Parameters.Count, dict.TryGetValue(OpenIddictConstants.Parameters.RedirectUri, out var ru) ? ru : null);
                            }
                            else
                            {
                                // Convert to OIDC error response early
                                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                                await ctx.Response.WriteAsJsonAsync(new
                                {
                                    error = result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject,
                                    error_description = result.ErrorDescription ?? "invalid request object"
                                });
                                return; // short-circuit
                            }
                        }
                        catch (Exception ex)
                        {
                            var log = ctx.RequestServices.GetRequiredService<ILogger<JarPreprocessingStartupFilter>>();
                            log.LogError(ex, "[JAR][MW] Middleware preprocessing failed");
                            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                            await ctx.Response.WriteAsJsonAsync(new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "invalid request object" });
                            return;
                        }
                    }
                }
                await nxt();
            });
            next(app);
        };    }
}
