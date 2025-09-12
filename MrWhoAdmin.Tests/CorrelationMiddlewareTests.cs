using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MrWho.Middleware;
using MrWho.Services;
using System.Security.Claims;

namespace MrWhoAdmin.Tests;

[TestClass]
public class CorrelationMiddlewareTests
{
    private static (RequestDelegate app, ServiceProvider sp) BuildApp(bool withUser)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ICorrelationContextAccessor, CorrelationContextAccessor>();
        var sp = services.BuildServiceProvider();

        RequestDelegate terminal = async ctx =>
        {
            var accessor = ctx.RequestServices.GetRequiredService<ICorrelationContextAccessor>();
            // Write correlation id into response body for assertion
            await ctx.Response.WriteAsync(accessor.Current.CorrelationId + "|" + accessor.Current.ActorType);
        };
        var logger = sp.GetRequiredService<ILogger<CorrelationMiddleware>>();
        var middleware = new CorrelationMiddleware(terminal, logger);
        RequestDelegate app = ctx => middleware.InvokeAsync(ctx);

        return (app, sp);
    }

    private static DefaultHttpContext CreateContext(ServiceProvider sp, bool withUser)
    {
        var httpCtx = new DefaultHttpContext { RequestServices = sp };
        if (withUser)
        {
            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "user-123"),
                new Claim(ClaimTypes.Name, "alice")
            }, "test");
            httpCtx.User = new ClaimsPrincipal(identity);
        }
        return httpCtx;
    }

    [TestMethod]
    public async Task Generates_New_CorrelationId_When_Absent()
    {
        var (app, sp) = BuildApp(false);
        var ctx = CreateContext(sp, false);
        await app(ctx);
        Assert.IsTrue(ctx.Response.Headers.ContainsKey("X-Correlation-Id"));
        var val = ctx.Response.Headers["X-Correlation-Id"].ToString();
        Assert.IsFalse(string.IsNullOrWhiteSpace(val));
    }

    [TestMethod]
    public async Task Preserves_Inbound_CorrelationId()
    {
        var (app, sp) = BuildApp(false);
        var ctx = CreateContext(sp, false);
        ctx.Request.Headers["X-Correlation-Id"] = "abc123";
        await app(ctx);
        Assert.AreEqual("abc123", ctx.Response.Headers["X-Correlation-Id"].ToString());
    }

    [TestMethod]
    public async Task Sets_Actor_Info_For_Authenticated_User()
    {
        var (app, sp) = BuildApp(true);
        var ctx = CreateContext(sp, true);
        await app(ctx);
        var accessor = sp.GetRequiredService<ICorrelationContextAccessor>();
        Assert.AreEqual("user", accessor.Current.ActorType);
        Assert.AreEqual("user-123", accessor.Current.ActorUserId);
    }
}
