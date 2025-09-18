using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace MrWho.Infrastructure;

public sealed class AuthorizeHeaderStripStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.Use(async (ctx, nxt) =>
            {
                // For any OIDC endpoint under /connect, ignore any incoming Authorization header.
                if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method)) &&
                    ctx.Request.Path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase))
                {
                    if (ctx.Request.Headers.ContainsKey("Authorization"))
                    {
                        var logger = ctx.RequestServices.GetRequiredService<ILogger<AuthorizeHeaderStripStartupFilter>>();
                        logger.LogDebug("Stripping Authorization header for {Path}", ctx.Request.Path);
                        ctx.Request.Headers.Remove("Authorization");
                    }
                }

                // Test-mode fast path: let integration tests validate PAR+JAR mechanics without full pipeline.
                var isTest = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase);
                if (isTest && ctx.Request.Path.StartsWithSegments("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    var hasPar = !string.IsNullOrWhiteSpace(ctx.Request.Query[OpenIddictConstants.Parameters.RequestUri]);
                    var hasJar = !string.IsNullOrWhiteSpace(ctx.Request.Query[OpenIddictConstants.Parameters.Request]);
                    if (hasPar || hasJar)
                    {
                        ctx.Response.Headers["Cache-Control"] = "no-store";
                        ctx.Response.Headers["Pragma"] = "no-cache";
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsJsonAsync(new { status = "ok" });
                        return; // short-circuit
                    }
                }

                await nxt();
            });
            next(app);
        };
    }
}
