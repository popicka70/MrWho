using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MrWho.Data;
using MrWho.Models;
using System.Security.Claims;

namespace MrWhoAdmin.Tests;

[TestClass]
public class ApplicationDbContextAuditTests
{
    private ApplicationDbContext CreateContext(out IHttpContextAccessor accessor)
    {
        accessor = new HttpContextAccessor();
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new ApplicationDbContext(options, accessor);
    }

    [TestMethod]
    public void AddEntity_Creates_AuditLog()
    {
        var ctx = CreateContext(out var accessor);
        var http = new DefaultHttpContext();
        http.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "user1"), new Claim(ClaimTypes.Name, "tester") }, "test"));
        accessor.HttpContext = http;

        ctx.Realms.Add(new Realm { Name = "r1", DisplayName = "Realm1", IsEnabled = true });
        ctx.SaveChanges();

        Assert.AreEqual(1, ctx.AuditLogs.Count());
        var log = ctx.AuditLogs.First();
        Assert.AreEqual("Realm", log.EntityType);
        Assert.AreEqual("Added", log.Action);
        Assert.AreEqual("user1", log.UserId);
    }

    [TestMethod]
    public void ModifyEntity_Creates_Modified_AuditLog()
    {
        var ctx = CreateContext(out var accessor);
        var http = new DefaultHttpContext();
        http.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "user2") }, "test"));
        accessor.HttpContext = http;

        var realm = new Realm { Name = "r2", DisplayName = "Realm2", IsEnabled = true };
        ctx.Realms.Add(realm);
        ctx.SaveChanges(); // audit 1

        realm.DisplayName = "RealmTwo";
        ctx.SaveChanges(); // audit 2

        Assert.AreEqual(2, ctx.AuditLogs.Count());
        var modLog = ctx.AuditLogs.OrderBy(l => l.OccurredAt).Last();
        Assert.AreEqual("Modified", modLog.Action);
        Assert.IsTrue(modLog.Changes?.Contains("DisplayName") ?? false);
    }

    [TestMethod]
    public void DeleteEntity_Creates_Deleted_AuditLog()
    {
        var ctx = CreateContext(out var accessor);
        accessor.HttpContext = new DefaultHttpContext();

        var realm = new Realm { Name = "r3", DisplayName = "Realm3", IsEnabled = true };
        ctx.Realms.Add(realm);
        ctx.SaveChanges();
        ctx.Realms.Remove(realm);
        ctx.SaveChanges();

        Assert.AreEqual(2, ctx.AuditLogs.Count()); // add + delete
        Assert.AreEqual("Deleted", ctx.AuditLogs.OrderBy(l => l.OccurredAt).Last().Action);
    }
}
