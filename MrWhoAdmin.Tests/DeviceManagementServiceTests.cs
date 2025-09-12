using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;

namespace MrWhoAdmin.Tests;

[TestClass]
public class DeviceManagementServiceTests
{
    private (ApplicationDbContext Db, DeviceManagementService Svc, IdentityUser User) Create()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        var db = new ApplicationDbContext(options);
        db.Database.EnsureCreated();
        var store = new UserStore<IdentityUser>(db);
        var userMgr = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), Array.Empty<IUserValidator<IdentityUser>>(), Array.Empty<IPasswordValidator<IdentityUser>>(), new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null, new LoggerFactory().CreateLogger<UserManager<IdentityUser>>());
        var user = new IdentityUser { UserName = "user@test", Email = "user@test" };
        userMgr.CreateAsync(user, "Pass123$!").GetAwaiter().GetResult();
        var logger = LoggerFactory.Create(b => b.AddDebug()).CreateLogger<DeviceManagementService>();
        var svc = new DeviceManagementService(db, userMgr, logger);
        return (db, svc, user);
    }

    [TestMethod]
    public async Task RegisterDevice_Then_GetAndRevoke()
    {
        var (db, svc, user) = Create();
        var device = await svc.RegisterDeviceAsync(user.Id, new RegisterDeviceRequest { DeviceId = "d1", DeviceName = "Phone", DeviceType = DeviceType.Phone, OperatingSystem = "Android" });
        Assert.IsTrue(device.IsActive, "Device should be active after registration");
        Assert.IsNotNull(await svc.GetDeviceAsync(user.Id, "d1"));
        var revoked = await svc.RevokeDeviceAsync(user.Id, "d1");
        Assert.IsTrue(revoked, "Revocation should return true");
        Assert.IsNull(await svc.GetDeviceAsync(user.Id, "d1"));
    }

    [TestMethod]
    public async Task QrSession_Flow_Approve_Complete()
    {
        var (db, svc, user) = Create();
        await svc.RegisterDeviceAsync(user.Id, new RegisterDeviceRequest { DeviceId = "dev1", DeviceName = "Tablet", DeviceType = DeviceType.Tablet, CanApproveLogins = true });
        var session = await svc.CreateQrSessionAsync(new CreateQrSessionRequest { ClientId = "clientA", UserId = string.Empty });
        var approve = await svc.ApproveQrSessionAsync(session.Token, user.Id, "dev1");
        Assert.IsTrue(approve, "Approval should succeed");
        var complete = await svc.CompleteQrSessionAsync(session.Token);
        Assert.IsTrue(complete, "Completion should succeed");
    }

    [TestMethod]
    public async Task MarkDeviceCompromised_Disables_Device()
    {
        var (db, svc, user) = Create();
        var device = await svc.RegisterDeviceAsync(user.Id, new RegisterDeviceRequest { DeviceId = "cD", DeviceName = "Chrome", DeviceType = DeviceType.Desktop });
        await svc.MarkDeviceCompromisedAsync("cD", "test");
        var reloaded = await svc.GetDeviceAsync(user.Id, "cD");
        Assert.IsNull(reloaded, "Compromised device should be inactive");
        Assert.AreEqual(1, await db.DeviceAuthenticationLogs.Where(l => l.ActivityType == DeviceAuthActivity.DeviceCompromised).CountAsync());
    }
}
