using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using MrWho.Data;
using MrWho.Models;
using MrWho.Options;
using MrWho.Services;

namespace MrWhoAdmin.Tests;

[TestClass]
public class DynamicClientCookieServiceTests
{
    private (DynamicClientCookieService Service, ApplicationDbContext Db, IServiceProvider Root, Mock<IOidcClientService> Oidc) Create(CookieSeparationMode mode)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<MrWhoOptions>(o => o.CookieSeparationMode = mode);
        services.AddDataProtection();
        services.AddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
        services.AddSingleton<IOptionsMonitorCache<CookieAuthenticationOptions>, OptionsCache<CookieAuthenticationOptions>>();
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        var oidc = new Mock<IOidcClientService>();
        services.AddSingleton(oidc.Object);
        var sp = services.BuildServiceProvider();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();
        var service = new DynamicClientCookieService(sp.GetRequiredService<IServiceScopeFactory>(), sp.GetRequiredService<IAuthenticationSchemeProvider>(), sp.GetRequiredService<IOptionsMonitorCache<CookieAuthenticationOptions>>(), sp.GetRequiredService<ILogger<DynamicClientCookieService>>());
        return (service, db, sp, oidc);
    }

    [TestMethod]
    public async Task StartAsync_ByClient_RegistersSchemes()
    {
        var (svc, db, sp, oidc) = Create(CookieSeparationMode.ByClient);
        var realm = new Realm { Name = "r", DisplayName = "R", IsEnabled = true };
        db.Realms.Add(realm); db.SaveChanges();
        var client = new Client { ClientId = "cX", Name = "ClientX", RealmId = realm.Id, Realm = realm, IsEnabled = true };
        db.Clients.Add(client); db.SaveChanges();
        oidc.Setup(o => o.GetEnabledClientsAsync()).ReturnsAsync(new[] { client });
        await svc.StartAsync(CancellationToken.None);
        var schemes = sp.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.IsNotNull(await schemes.GetSchemeAsync("Identity.Application.cX"));
    }

    //[TestMethod]
    //public async Task StartAsync_ByRealm_RegistersRealmScheme()
    //{
    //    var (svc, db, sp, oidc) = Create(CookieSeparationMode.ByRealm);
    //    var realm = new Realm { Name = "realmZ", DisplayName = "RealmZ", IsEnabled = true };
    //    db.Realms.Add(realm); db.SaveChanges();
    //    var client = new Client { ClientId = "cY", Name = "CY", RealmId = realm.Id, Realm = realm, IsEnabled = true };
    //    db.Clients.Add(client); db.SaveChanges();
    //    await svc.StartAsync(CancellationToken.None);
    //    var schemes = sp.GetRequiredService<IAuthenticationSchemeProvider>();
    //    Assert.IsNotNull(await schemes.GetSchemeAsync("Identity.Application.realmZ"));
    //}
}
