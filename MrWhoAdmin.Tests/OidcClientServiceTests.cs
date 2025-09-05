using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;

namespace MrWhoAdmin.Tests;

[TestClass]
public class OidcClientServiceTests
{
    private (ApplicationDbContext Db, OidcClientService Service, Mock<IOpenIddictApplicationManager> AppMgr, Mock<IOpenIddictScopeManager> ScopeMgr, UserManager<IdentityUser> UserMgr) Create()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var db = new ApplicationDbContext(options);
        db.Database.EnsureCreated();

        var appMgr = new Mock<IOpenIddictApplicationManager>();
        appMgr.Setup(m => m.FindByClientIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync((object?)null);
        appMgr.Setup(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>())).Returns(ValueTask.FromResult<object?>(null));
        appMgr.Setup(m => m.UpdateAsync(It.IsAny<object>(), It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>())).Returns(ValueTask.CompletedTask);

        var scopeMgr = new Mock<IOpenIddictScopeManager>();
        scopeMgr.Setup(s => s.FindByNameAsync(StandardScopes.MrWhoUse, It.IsAny<CancellationToken>())).ReturnsAsync((object?)null);
        scopeMgr.Setup(s => s.CreateAsync(It.IsAny<OpenIddictScopeDescriptor>(), It.IsAny<CancellationToken>())).Returns(ValueTask.FromResult<object?>(null));

        var store = new UserStore<IdentityUser>(db);
        var userMgr = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), Array.Empty<IUserValidator<IdentityUser>>(), Array.Empty<IPasswordValidator<IdentityUser>>(), new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null, new Mock<ILogger<UserManager<IdentityUser>>>().Object);

        var logger = LoggerFactory.Create(b => b.AddDebug()).CreateLogger<OidcClientService>();
        var service = new OidcClientService(db, appMgr.Object, scopeMgr.Object, userMgr, logger);
        return (db, service, appMgr, scopeMgr, userMgr);
    }

    [TestMethod]
    public async Task InitializeEssentialData_Creates_Admin_Realm_And_Client()
    {
        var (db, svc, appMgr, scopeMgr, _) = Create();
        await svc.InitializeEssentialDataAsync();
        db.Realms.Any(r => r.Name == "admin").Should().BeTrue();
        db.Clients.Any(c => c.ClientId == MrWhoConstants.AdminClientId).Should().BeTrue();
        appMgr.Verify(m => m.CreateAsync(It.Is<OpenIddictApplicationDescriptor>(d => d.ClientId == MrWhoConstants.AdminClientId), It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        scopeMgr.Verify(s => s.CreateAsync(It.Is<OpenIddictScopeDescriptor>(d => d.Name == StandardScopes.MrWhoUse), It.IsAny<CancellationToken>()), Times.AtLeastOnce());
    }

    [TestMethod]
    public async Task SyncClient_Skips_Confidential_Without_Secret()
    {
        var (db, svc, appMgr, _, _) = Create();
        var realm = new Realm { Name = "r1", DisplayName = "R1", IsEnabled = true };
        db.Realms.Add(realm); db.SaveChanges();
        var client = new Client { ClientId = "c1", Name = "C1", RealmId = realm.Id, Realm = realm, ClientType = ClientType.Confidential, RequireClientSecret = true, ClientSecret = null };
        db.Clients.Add(client); db.SaveChanges();
        await svc.SyncClientWithOpenIddictAsync(client);
        appMgr.Verify(m => m.CreateAsync(It.IsAny<OpenIddictApplicationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }
}
