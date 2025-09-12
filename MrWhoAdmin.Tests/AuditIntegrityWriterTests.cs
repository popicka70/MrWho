using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MrWho.Data;
using MrWho.Services;
using MrWho.Models;
using Microsoft.AspNetCore.Http;

namespace MrWhoAdmin.Tests;

[TestClass]
public class AuditIntegrityWriterTests
{
    private ServiceProvider BuildServices()
    {
        var sc = new ServiceCollection();
        sc.AddLogging();
        sc.AddHttpContextAccessor(); // required for CorrelationContextAccessor
        sc.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        sc.AddSingleton<ICorrelationContextAccessor, CorrelationContextAccessor>(); // required by writer
        sc.AddScoped<IIntegrityHashService, IntegrityHashService>(); // hash service
        sc.AddScoped<IAuditIntegrityWriter, AuditIntegrityWriter>();
        sc.AddScoped<IAuditIntegrityVerificationService, AuditIntegrityVerificationService>();
        return sc.BuildServiceProvider();
    }

    [TestMethod]
    public async Task Writes_Chain_With_No_Breaks()
    {
        var sp = BuildServices();
        // seed HttpContext for accessor
        sp.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext();
        var writer = sp.GetRequiredService<IAuditIntegrityWriter>();
        var verifier = sp.GetRequiredService<IAuditIntegrityVerificationService>();
        for (int i = 0; i < 3; i++)
        {
            await writer.WriteAsync(new AuditIntegrityWriteRequest("test", $"act{i}", ActorType: "user", ActorId: "u1"));
        }
        var result = await verifier.VerifyAsync(ct: CancellationToken.None);
        Assert.AreEqual(0, result.Breaks);
        Assert.AreEqual(3, result.TotalScanned);
    }

    [TestMethod]
    public async Task Detects_Tampering()
    {
        var sp = BuildServices();
        sp.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext();
        var writer = sp.GetRequiredService<IAuditIntegrityWriter>();
        var verifier = sp.GetRequiredService<IAuditIntegrityVerificationService>();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        for (int i = 0; i < 5; i++)
        {
            await writer.WriteAsync(new AuditIntegrityWriteRequest("test", $"act{i}"));
        }
        // Tamper: modify DataJson of second record
        var second = await db.AuditIntegrityRecords.OrderBy(r => r.Id).Skip(1).FirstAsync();
        second.DataJson = "{\"tampered\":true}";
        db.Update(second);
        await db.SaveChangesAsync();
        var result = await verifier.VerifyAsync(ct: CancellationToken.None);
        Assert.IsTrue(result.Breaks > 0);
        Assert.IsNotNull(result.FirstBrokenId);
    }
}
