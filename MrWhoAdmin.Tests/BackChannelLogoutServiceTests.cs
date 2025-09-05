using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Net;
using System.Net.Http;
using System.Text;

namespace MrWhoAdmin.Tests;

[TestClass]
public class BackChannelLogoutServiceTests
{
    private sealed class TestHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest; public HttpStatusCode Status = HttpStatusCode.OK;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent("ok", Encoding.UTF8, "text/plain") });
        }
    }

    private (BackChannelLogoutService Service, TestHandler Handler, ApplicationDbContext Db, IServiceProvider Root, Mock<IOpenIddictAuthorizationManager> AuthzMgr, Mock<IOpenIddictApplicationManager> AppMgr) Create()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var handler = new TestHandler();
        services.AddHttpClient("test").ConfigurePrimaryHttpMessageHandler(() => handler);
        services.AddSingleton<IHttpClientFactory>(sp => sp.GetRequiredService<IHttpClientFactory>()); // default

        var options = new OpenIddictServerOptions();
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(new TestOptionsMonitor<OpenIddictServerOptions>(options));

        var authzMgr = new Mock<IOpenIddictAuthorizationManager>();
        var appMgr = new Mock<IOpenIddictApplicationManager>();
        services.AddSingleton(authzMgr.Object);
        services.AddSingleton(appMgr.Object);

        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        var sp = services.BuildServiceProvider();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();

        var svc = new BackChannelLogoutService(sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<ILogger<BackChannelLogoutService>>(), sp, sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>());
        return (svc, handler, db, sp, authzMgr, appMgr);
    }

    private sealed class TestOptionsMonitor<T> : IOptionsMonitor<T> where T : class, new()
    {
        private readonly T _value; public TestOptionsMonitor(T v) { _value = v; }
        public T CurrentValue => _value; public T Get(string? name) => _value; public IDisposable OnChange(Action<T, string?> listener) => new Dummy(); private sealed class Dummy : IDisposable { public void Dispose() { } }
    }

    //[TestMethod]
    //public async Task NotifyClientLogout_NoClientUri_Skips()
    //{
    //    var (svc, handler, db, sp, authzMgr, appMgr) = Create();
    //    db.Clients.Add(new Client { ClientId = "unknown_client", Name = "X", Realm = new Realm { Name = "r", DisplayName = "R", IsEnabled = true }, RealmId = Guid.NewGuid().ToString(), IsEnabled = true });
    //    db.SaveChanges();
    //    await svc.NotifyClientLogoutAsync("unknown_client", "subj", "sess");
    //    Assert.IsNull(handler.LastRequest, "No request should be sent without logout URI");
    //}

    //[TestMethod]
    //public async Task CreateLogoutToken_ReturnsJwtOrJson()
    //{
    //    var (svc, _, _, _, _, _) = Create();
    //    var token = await svc.CreateLogoutTokenAsync("client", "subj", "sess");
    //    Assert.IsFalse(string.IsNullOrEmpty(token), "Token should be generated");
    //}
}
