using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using System.Diagnostics;
using Microsoft.AspNetCore.Http; // added

namespace MrWhoAdmin.Tests;

[TestClass]
public class IntegrityHashServiceTests
{
    [TestMethod]
    public void Deterministic_Hash_Output()
    {
        IIntegrityHashService svc = new IntegrityHashService();
        var canonical = "A|2025-01-01T00:00:00.0000000Z|cat|act|user|u1|subj|s1|realm|corr|{}";
        var h1 = svc.ComputeChainHash(canonical, null, 1);
        var h2 = svc.ComputeChainHash(canonical, "", 1); // null and empty treated same for first record
        Assert.AreEqual(h1, h2, "Hash should be deterministic and treat null/empty previous hash equally for first record");

        var h3 = svc.ComputeChainHash(canonical, "ABC", 1);
        Assert.AreNotEqual(h1, h3, "Changing previous hash should change chain hash");

        var h4 = svc.ComputeChainHash(canonical, null, 2);
        Assert.AreNotEqual(h1, h4, "Changing version should change hash");
    }

    [TestMethod]
    public async Task Writer_Performance_Average_Under_3ms()
    {
        // NOTE: This is a coarse micro benchmark. If it becomes flaky in CI you may relax to <5ms.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpContextAccessor();
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddSingleton<ICorrelationContextAccessor, CorrelationContextAccessor>();
        services.AddScoped<IIntegrityHashService, IntegrityHashService>();
        services.AddScoped<IAuditIntegrityWriter, AuditIntegrityWriter>();
        var sp = services.BuildServiceProvider();

        // Seed an HttpContext for correlation id stability
        var http = new DefaultHttpContext();
        sp.GetRequiredService<IHttpContextAccessor>().HttpContext = http;

        var writer = sp.GetRequiredService<IAuditIntegrityWriter>();
        const int iterations = 50; // keep low to avoid long test time
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            await writer.WriteAsync(new AuditIntegrityWriteRequest(
                Category: "perf",
                Action: $"act{i}",
                ActorType: "system"
            ));
        }
        sw.Stop();
        var avgMs = sw.Elapsed.TotalMilliseconds / iterations;
        Assert.IsTrue(avgMs < 3.0, $"Average write time {avgMs:F2}ms exceeded 3ms target");
    }
}
