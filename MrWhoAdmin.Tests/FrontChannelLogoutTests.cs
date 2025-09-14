using System.Security.Claims;
using Microsoft.AspNetCore.Http; // for HttpContext, DefaultHttpContext, HostString
using Microsoft.AspNetCore.Mvc; // for SignOutResult
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Endpoints.Auth;
using MrWho.Handlers.Auth;
using MrWho.Models;
using MrWho.Options;
using MrWho.Services; // ILogoutHelper
using MrWho.Services.Mediator;

namespace MrWhoAdmin.Tests;

[TestClass]
public class FrontChannelLogoutTests
{
    private sealed class FakeLogoutHelper : ILogoutHelper
    {
        public bool IsOidcLogoutRequest(HttpContext http) => false; // force direct path
        public bool UseGlobalLogout(HttpContext http) => false; // client-only signout for test
        public Task<string?> TryGetClientIdFromRequestAsync(HttpContext http) => Task.FromResult<string?>(null);
        public Task SignOutClientOnlyAsync(HttpContext http, string? clientId) { return Task.CompletedTask; }
        public Task SignOutGlobalAsync(HttpContext http, string? initiatingClientId) { return Task.CompletedTask; }
        public void DeleteCookieAcrossDomains(HttpContext http, string cookieName) { }
    }

    private sealed class FakeLogoutHelperOidc : ILogoutHelper
    {
        public bool IsOidcLogoutRequest(HttpContext http) => true; // force OIDC path
        public bool UseGlobalLogout(HttpContext http) => false;
        public Task<string?> TryGetClientIdFromRequestAsync(HttpContext http) => Task.FromResult<string?>("client_a");
        public Task SignOutClientOnlyAsync(HttpContext http, string? clientId) => Task.CompletedTask;
        public Task SignOutGlobalAsync(HttpContext http, string? initiatingClientId) => Task.CompletedTask;
        public void DeleteCookieAcrossDomains(HttpContext http, string cookieName) { }
    }

    private static ApplicationDbContext CreateDb(out IServiceProvider sp)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        sp = services.BuildServiceProvider();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();
        return db;
    }

    private static ClaimsPrincipal BuildPrincipalWithSid(string sid)
    {
        var id = new ClaimsIdentity("test");
        id.AddClaim(new Claim("sub", "user1"));
        id.AddClaim(new Claim("sid", sid));
        return new ClaimsPrincipal(id);
    }

    [TestMethod]
    public async Task Logout_Enumerates_FrontChannel_Iframes_For_Clients()
    {
        var logoutHelper = new FakeLogoutHelper();
        var options = Options.Create(new MrWhoOptions());
        var logger = NullLogger<LogoutGetHandler>.Instance;
        var db = CreateDb(out var sp);

        // Seed realm
        var realm = new Realm { Id = Guid.NewGuid().ToString(), Name = "default", DisplayName = "Default", IsEnabled = true };
        db.Realms.Add(realm);

        db.Clients.AddRange(
            new Client { Id = Guid.NewGuid().ToString(), ClientId = "client_a", Name = "Client A", IsEnabled = true, RealmId = realm.Id, FrontChannelLogoutUri = "https://client-a.example.com/fcl" },
            new Client { Id = Guid.NewGuid().ToString(), ClientId = "client_b", Name = "Client B", IsEnabled = true, RealmId = realm.Id, FrontChannelLogoutUri = "https://client-b.example.com/fcl" },
            new Client { Id = Guid.NewGuid().ToString(), ClientId = "client_c", Name = "Client C", IsEnabled = true, RealmId = realm.Id } // no URI -> skipped
        );
        await db.SaveChangesAsync();

        // Build HttpContext
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("server.test");
        context.User = BuildPrincipalWithSid("sid123");
        context.RequestServices = sp; // minimal; db context resolved via handler DI

        var handler = new LogoutGetHandler(logger, logoutHelper, db, options);
        var req = new LogoutGetRequest(context, null, null);

        var result = await handler.Handle(req, CancellationToken.None);

        // Validate iframes list placed in HttpContext.Items
        Assert.IsTrue(context.Items.TryGetValue("FrontChannelLogoutIframes", out var val), "Iframe list not populated");
        var list = val as IEnumerable<string> ?? Array.Empty<string>();
        var arr = list.ToArray();
        Assert.AreEqual(2, arr.Length, "Expected two iframe URLs for clients with URIs");
        Assert.IsTrue(arr.All(u => u.Contains("sid=sid123")), "Iframe URLs must include sid parameter");
        Assert.IsTrue(arr.All(u => u.Contains("iss=https%3A%2F%2Fserver.test")), "Iframe URLs must include issuer");
    }

    [TestMethod]
    public async Task Oidc_EndSession_Path_Populates_Iframes_And_Returns_SignOutResult()
    {
        var logoutHelper = new FakeLogoutHelperOidc();
        var options = Options.Create(new MrWhoOptions());
        var logger = NullLogger<LogoutGetHandler>.Instance;
        var db = CreateDb(out var sp);
        var realm = new Realm { Id = Guid.NewGuid().ToString(), Name = "default", DisplayName = "Default", IsEnabled = true };
        db.Realms.Add(realm);
        db.Clients.AddRange(
            new Client { Id = Guid.NewGuid().ToString(), ClientId = "client_a", Name = "Client A", IsEnabled = true, RealmId = realm.Id, FrontChannelLogoutUri = "https://client-a.example.com/fcl" },
            new Client { Id = Guid.NewGuid().ToString(), ClientId = "client_b", Name = "Client B", IsEnabled = true, RealmId = realm.Id, FrontChannelLogoutUri = "https://client-b.example.com/fcl" }
        );
        await db.SaveChangesAsync();

        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("server.test");
        // Simulate OpenIddict end-session request by adding sid claim
        context.User = BuildPrincipalWithSid("sid456");
        context.RequestServices = sp;

        var handler = new LogoutGetHandler(logger, logoutHelper, db, options);
        var req = new LogoutGetRequest(context, null, null);
        var result = await handler.Handle(req, CancellationToken.None);

        Assert.IsInstanceOfType(result, typeof(SignOutResult), "Expected SignOutResult for OIDC end-session path");
        Assert.IsTrue(context.Items.TryGetValue("FrontChannelLogoutIframes", out var val), "Iframe list missing for OIDC path");
        var list = (val as IEnumerable<string>)?.ToArray() ?? Array.Empty<string>();
        Assert.AreEqual(2, list.Length, "Expected two iframe URLs");
        Assert.IsTrue(list.All(u => u.Contains("sid=sid456")), "Each iframe should include sid param");
    }
}
