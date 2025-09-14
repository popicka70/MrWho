using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;

namespace MrWhoAdmin.Tests;

[TestClass]
public class UserRealmValidationServiceTests
{
    private class Fixture
    {
        public ApplicationDbContext Db { get; }
        public UserManager<IdentityUser> UserManager { get; }
        public IdentityUser User { get; } = new IdentityUser { UserName = "u@test", Email = "u@test" };
        public Client Client { get; }
        public UserRealmValidationService Service { get; }

        public Fixture(bool assignUser = true, bool clientEnabled = true, bool realmEnabled = true)
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            Db = new ApplicationDbContext(options);
            Db.Database.EnsureCreated();

            var realm = new Realm { Name = "r1", DisplayName = "Realm", IsEnabled = realmEnabled };
            Db.Realms.Add(realm);
            Db.SaveChanges();

            Client = new Client
            {
                ClientId = "c1",
                Name = "Client1",
                RealmId = realm.Id,
                IsEnabled = clientEnabled,
                Realm = realm
            };
            Db.Clients.Add(Client);
            Db.SaveChanges();

            var store = new UserStore<IdentityUser>(Db);
            UserManager = new UserManager<IdentityUser>(store, Options.Create(new IdentityOptions()), new PasswordHasher<IdentityUser>(),
                Array.Empty<IUserValidator<IdentityUser>>(), Array.Empty<IPasswordValidator<IdentityUser>>(),
                new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), new ServiceCollection().BuildServiceProvider(), new LoggerFactory().CreateLogger<UserManager<IdentityUser>>());

            var res = UserManager.CreateAsync(User, "Pass123$!").GetAwaiter().GetResult();
            if (!res.Succeeded)
            {
                throw new InvalidOperationException("Failed to create user: " + string.Join(',', res.Errors.Select(e => e.Description)));
            }

            if (assignUser)
            {
                Db.ClientUsers.Add(new ClientUser { ClientId = Client.Id, UserId = User.Id });
                Db.SaveChanges();
            }

            Service = new UserRealmValidationService(Db, UserManager, new LoggerFactory().CreateLogger<UserRealmValidationService>());
        }
    }

    [TestMethod]
    public async Task ValidateUserRealmAccess_Succeeds_WhenUserAssignedAndEnabled()
    {
        var fx = new Fixture();
        var res = await fx.Service.ValidateUserRealmAccessAsync(fx.User, fx.Client.ClientId);
        Assert.IsTrue(res.IsValid);
        Assert.AreEqual("r1", res.ClientRealm);
    }

    [TestMethod]
    public async Task ValidateUserRealmAccess_Fails_WhenClientDisabled()
    {
        var fx = new Fixture(clientEnabled: false);
        var res = await fx.Service.ValidateUserRealmAccessAsync(fx.User, fx.Client.ClientId);
        Assert.IsFalse(res.IsValid);
        Assert.AreEqual("CLIENT_DISABLED", res.ErrorCode);
    }

    [TestMethod]
    public async Task ValidateUserRealmAccess_Fails_WhenRealmDisabled()
    {
        var fx = new Fixture(realmEnabled: false);
        var res = await fx.Service.ValidateUserRealmAccessAsync(fx.User, fx.Client.ClientId);
        Assert.IsFalse(res.IsValid);
        Assert.AreEqual("CLIENT_DISABLED", res.ErrorCode);
    }

    [TestMethod]
    public async Task ValidateUserRealmAccess_Fails_WhenUserNotAssigned()
    {
        var fx = new Fixture(assignUser: false);
        var res = await fx.Service.ValidateUserRealmAccessAsync(fx.User, fx.Client.ClientId);
        Assert.IsFalse(res.IsValid);
        Assert.AreEqual("CLIENT_USER_NOT_ASSIGNED", res.ErrorCode);
    }

    [TestMethod]
    public async Task ValidateUserRealmAccess_Fails_WhenClientNotFound()
    {
        var fx = new Fixture();
        var res = await fx.Service.ValidateUserRealmAccessAsync(fx.User, "missing");
        Assert.IsFalse(res.IsValid);
        Assert.AreEqual("CLIENT_NOT_FOUND", res.ErrorCode);
    }
}
