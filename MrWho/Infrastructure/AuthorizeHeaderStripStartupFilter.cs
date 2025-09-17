using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MrWho.Infrastructure;

/// <summary>
/// Minimal startup filter that strips the Authorization header for /connect/authorize requests
/// to prevent the OpenIddict validation handler from treating it as a protected API call.
/// This avoids ID2004 invalid_token errors during the authorization flow when a bearer is present.
/// </summary>
public sealed class AuthorizeHeaderStripStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.Use(async (ctx, nxt) =>
            {
                if ((HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsPost(ctx.Request.Method)) &&
                    ctx.Request.Path.StartsWithSegments("/connect/authorize", StringComparison.OrdinalIgnoreCase))
                {
                    if (ctx.Request.Headers.ContainsKey("Authorization"))
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
