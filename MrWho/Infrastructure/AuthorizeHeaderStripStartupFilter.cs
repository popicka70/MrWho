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
                // Only strip Authorization for /connect/authorize and /connect/par
                if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method)))
                {
                    var path = ctx.Request.Path;
                    if ((path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase) ||
                         path.Equals("/connect/par", StringComparison.OrdinalIgnoreCase)) &&
                        ctx.Request.Headers.ContainsKey("Authorization"))
                    {
                        var logger = ctx.RequestServices.GetRequiredService<ILogger<AuthorizeHeaderStripStartupFilter>>();
                        logger.LogDebug("Stripping Authorization header for {Path}", ctx.Request.Path);
                        ctx.Request.Headers.Remove("Authorization");
                    }
                }

                await nxt();
            });
            next(app);
        };
    }
}
