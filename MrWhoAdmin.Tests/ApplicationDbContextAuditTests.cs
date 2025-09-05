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

        ctx.AuditLogs.Count().Should().Be(1);
        var log = ctx.AuditLogs.First();
        log.EntityType.Should().Be("Realm");
        log.Action.Should().Be("Added");
        log.UserId.Should().Be("user1");
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

        ctx.AuditLogs.Count().Should().Be(2);
        var modLog = ctx.AuditLogs.OrderBy(l => l.OccurredAt).Last();
        modLog.Action.Should().Be("Modified");
        modLog.Changes.Should().Contain("DisplayName");
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

        ctx.AuditLogs.Count().Should().Be(2); // add + delete
        ctx.AuditLogs.OrderBy(l => l.OccurredAt).Last().Action.Should().Be("Deleted");
    }
}
