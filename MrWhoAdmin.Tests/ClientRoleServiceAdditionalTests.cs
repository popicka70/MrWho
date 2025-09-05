using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;

namespace MrWhoAdmin.Tests;

[TestClass]
public class ClientRoleServiceAdditionalTests
{
    private (ClientRoleService Service, ApplicationDbContext Db, IdentityUser User, Client Client) Create()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var db = new ApplicationDbContext(options);
        db.Database.EnsureCreated();
        var realm = new Realm { Name = Guid.NewGuid().ToString("N").Substring(0,8), DisplayName = "R", IsEnabled = true };
        db.Realms.Add(realm); db.SaveChanges();
        var client = new Client { ClientId = Guid.NewGuid().ToString("N"), Name = "C", Realm = realm, RealmId = realm.Id };
        db.Clients.Add(client); db.SaveChanges();
        var store = new UserStore<IdentityUser>(db);
        var userMgr = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), Array.Empty<IUserValidator<IdentityUser>>(), Array.Empty<IPasswordValidator<IdentityUser>>(), new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null, LoggerFactory.Create(b => b.AddDebug()).CreateLogger<UserManager<IdentityUser>>());
        var user = new IdentityUser { UserName = "u@t", Email = "u@t" };
        userMgr.CreateAsync(user, "Pass123$!").GetAwaiter().GetResult();
        var service = new ClientRoleService(db, userMgr, new MemoryCache(new MemoryCacheOptions()), LoggerFactory.Create(b => b.AddDebug()).CreateLogger<ClientRoleService>());
        return (service, db, user, client);
    }

    [TestMethod]
    public async Task AddRole_Is_Idempotent()
    {
        var (svc, _, user, client) = Create();
        await svc.AddRoleToUserAsync(user.Id, client.ClientId, "alpha");
        await svc.AddRoleToUserAsync(user.Id, client.ClientId, "alpha");
        var roles = await svc.GetClientRolesAsync(user.Id, client.ClientId);
        roles.Count(r => r == "alpha").Should().Be(1);
    }

    [TestMethod]
    public async Task Role_Lookup_Is_Case_Insensitive()
    {
        var (svc, _, user, client) = Create();
        await svc.AddRoleToUserAsync(user.Id, client.ClientId, "Beta");
        await svc.RemoveRoleFromUserAsync(user.Id, client.ClientId, "beta");
        (await svc.GetClientRolesAsync(user.Id, client.ClientId)).Should().NotContain("Beta");
    }
}
