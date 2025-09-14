using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;

namespace MrWhoAdmin.Tests;

[TestClass]
public class ClientRoleServiceTests
{
    private class TestFixture
    {
        public ApplicationDbContext Db { get; }
        public UserManager<IdentityUser> UserManager { get; }
        public IMemoryCache Cache { get; } = new MemoryCache(new MemoryCacheOptions());
        public ClientRoleService Service { get; }

        public IdentityUser User { get; } = new IdentityUser { UserName = "user@example.com", Email = "user@example.com" };
        public Client Client { get; }

        public TestFixture()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            Db = new ApplicationDbContext(options);
            Db.Database.EnsureCreated();

            // Add realm and client required for FK relationships
            var realm = new Realm { Name = "realm", DisplayName = "Realm", IsEnabled = true };
            Db.Realms.Add(realm);
            Db.SaveChanges();

            Client = new Client
            {
                ClientId = "test_client",
                Name = "Test Client",
                RealmId = realm.Id,
                Realm = realm
            };
            Db.Clients.Add(Client);
            Db.SaveChanges();

            // Configure UserManager with in-memory store
            var store = new UserStore<IdentityUser>(Db);
            var userMgrLogger = new Mock<ILogger<UserManager<IdentityUser>>>();
            UserManager = new UserManager<IdentityUser>(store, Options.Create(new IdentityOptions()), new PasswordHasher<IdentityUser>(),
                Array.Empty<IUserValidator<IdentityUser>>(), Array.Empty<IPasswordValidator<IdentityUser>>(),
                new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), new ServiceCollection().BuildServiceProvider(), userMgrLogger.Object);

            // Create user
            var createResult = UserManager.CreateAsync(User, "Pass123$!").GetAwaiter().GetResult();
            if (!createResult.Succeeded) {
                throw new InvalidOperationException("Failed creating test user: " + string.Join(',', createResult.Errors.Select(e => e.Description)));
            }

            // Create a global role and assign to user so global role retrieval path is exercised
            Db.Roles.Add(new IdentityRole { Name = "globalAdmin", NormalizedName = "GLOBALADMIN" });
            Db.SaveChanges();
            UserManager.AddToRoleAsync(User, "globalAdmin").GetAwaiter().GetResult();

            var logger = LoggerFactory.Create(b => b.AddDebug().SetMinimumLevel(LogLevel.Warning))
                .CreateLogger<ClientRoleService>();
            Service = new ClientRoleService(Db, UserManager, Cache, logger);
        }
    }

    [TestMethod]
    public async Task AddRoleToUser_CreatesRoleAndLink()
    {
        var fx = new TestFixture();
        await fx.Service.AddRoleToUserAsync(fx.User.Id, fx.Client.ClientId, "editor");

        var roles = await fx.Service.GetClientRolesAsync(fx.User.Id, fx.Client.ClientId);
        Assert.IsTrue(roles.Contains("editor"), "Role 'editor' should be assigned");

        // Cache hit path
        var rolesSecond = await fx.Service.GetClientRolesAsync(fx.User.Id, fx.Client.ClientId);
        CollectionAssert.AreEquivalent(roles.ToList(), rolesSecond.ToList(), "Cached roles should match first retrieval");
    }

    [TestMethod]
    public async Task RemoveRoleFromUser_RemovesLink()
    {
        var fx = new TestFixture();
        await fx.Service.AddRoleToUserAsync(fx.User.Id, fx.Client.ClientId, "viewer");
        Assert.IsTrue((await fx.Service.GetClientRolesAsync(fx.User.Id, fx.Client.ClientId)).Contains("viewer"));

        await fx.Service.RemoveRoleFromUserAsync(fx.User.Id, fx.Client.ClientId, "viewer");
        Assert.IsFalse((await fx.Service.GetClientRolesAsync(fx.User.Id, fx.Client.ClientId)).Contains("viewer"));
    }

    [TestMethod]
    [DataRow(RoleInclusion.GlobalOnly, true, false)]
    [DataRow(RoleInclusion.ClientOnly, false, true)]
    [DataRow(RoleInclusion.GlobalAndClient, true, true)]
    public async Task GetEffectiveRoles_Works(RoleInclusion inclusion, bool expectGlobal, bool expectClient)
    {
        var fx = new TestFixture();
        await fx.Service.AddRoleToUserAsync(fx.User.Id, fx.Client.ClientId, "clientRole");
        var roles = await fx.Service.GetEffectiveRolesAsync(fx.User.Id, fx.Client.ClientId, inclusion);

        var hasGlobal = roles.Any(r => r.Equals("globalAdmin", StringComparison.OrdinalIgnoreCase));
        Assert.AreEqual(expectGlobal, hasGlobal, $"Global role expectation mismatch for {inclusion}");
        var hasClient = roles.Contains("clientRole");
        Assert.AreEqual(expectClient, hasClient, $"Client role expectation mismatch for {inclusion}");
    }
}
