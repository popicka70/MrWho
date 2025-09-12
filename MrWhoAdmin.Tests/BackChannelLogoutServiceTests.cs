using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Linq; // added for LINQ on diagnostics
using Microsoft.AspNetCore.Http; // added for IHttpContextAccessor

namespace MrWhoAdmin.Tests;

[TestClass]
public class BackChannelLogoutServiceTests
{
    [TestInitialize]
    public void Init() => BackChannelLogoutService.ClearDiagnostics();

    private static string[] FetchDiagForClient(string clientId)
    {
        var all = BackChannelLogoutService.GetRecentDiagnostics();
        if (all.Length == 0) return new[] { "-- global diagnostics empty --" };
        var filtered = all.Where(l => l.Contains($"client={clientId}")).ToArray();
        if (filtered.Length == 0)
        {
            filtered = new[] { "-- no filtered lines --" }.Concat(all).ToArray();
        }
        return filtered;
    }

    private sealed class TestHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest; 
        public HttpStatusCode Status = HttpStatusCode.OK;
        public bool SimulateTimeout;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (SimulateTimeout)
            {
                throw new TaskCanceledException("timeout");
            }
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent("ok", Encoding.UTF8, "text/plain") });
        }
    }

    private sealed class TestOptionsMonitor<T> : IOptionsMonitor<T> where T : class, new()
    {
        private readonly T _value; public TestOptionsMonitor(T v) { _value = v; }
        public T CurrentValue => _value; public T Get(string? name) => _value; public IDisposable OnChange(Action<T, string?> listener) => new Dummy(); private sealed class Dummy : IDisposable { public void Dispose() { } }
    }

    private sealed class FakeScheduler : IBackChannelLogoutRetryScheduler
    {
        public List<BackChannelLogoutRetryWork> Scheduled { get; } = new();
        public List<(string clientId,string sessionId,int attempt,bool success,string? status,string? error)> AttemptOutcomes { get; } = new();
        public List<(string clientId,string sessionId,int attempts)> Exhausted { get; } = new();
        public void ScheduleRetry(BackChannelLogoutRetryWork work)
        {
            // mimic real scheduler increment behavior
            var scheduled = work with { Attempt = work.Attempt + 1 };
            Scheduled.Add(scheduled);
        }
        public void ReportAttemptOutcome(string clientId, string subject, string sessionId, int attempt, bool success, string? status, string? error)
            => AttemptOutcomes.Add((clientId, sessionId, attempt, success, status, error));
        public void ReportExhausted(string clientId, string subject, string sessionId, int attempts)
            => Exhausted.Add((clientId, sessionId, attempts));
    }

    private (BackChannelLogoutService Service, TestHandler Handler, ApplicationDbContext Db, FakeScheduler Scheduler, string ClientId) Create(bool withClient = true, HttpStatusCode status = HttpStatusCode.OK, bool timeout = false, string clientIdOverride = "mrwho_demo1")
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>(); // ensure available for any context filters
        var handler = new TestHandler { Status = status, SimulateTimeout = timeout };
        services.AddHttpClient("backchannel").ConfigurePrimaryHttpMessageHandler(() => handler);
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(new byte[32]), Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256));
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(new TestOptionsMonitor<OpenIddictServerOptions>(options));
        services.AddSingleton(new Mock<IOpenIddictAuthorizationManager>().Object);
        services.AddSingleton(new Mock<IOpenIddictApplicationManager>().Object);

        // Deterministic database name per client id so scoped contexts share state
        var dbName = $"bcl_{clientIdOverride}";
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(dbName));

        var scheduler = new FakeScheduler();
        services.AddSingleton<IBackChannelLogoutRetryScheduler>(scheduler);
        var sp = services.BuildServiceProvider();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();
        var clientId = clientIdOverride; // choose id
        if (withClient)
        {
            if (!db.Clients.Any(c => c.ClientId == clientId))
            {
                db.Clients.Add(new Client
                {
                    Id = Guid.NewGuid().ToString(),
                    ClientId = clientId,
                    Name = clientId,
                    IsEnabled = true,
                    RealmId = Guid.NewGuid().ToString(),
                    BackChannelLogoutUri = $"https://{clientId}.example.com/signout-backchannel"
                });
                db.SaveChanges();
            }
            // Verify persistence immediately
            if (!db.Clients.AsNoTracking().Any(c => c.ClientId == clientId))
            {
                Assert.Inconclusive($"Client '{clientId}' was not persisted to in-memory store (dbName={dbName}). Entries: {db.Clients.Count()}");
            }
        }
        var svc = new BackChannelLogoutService(sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<ILogger<BackChannelLogoutService>>(), sp, sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>(), null, scheduler);
        return (svc, handler, db, scheduler, clientId);
    }

    [TestMethod]
    public async Task Success_Does_Not_Schedule_Retry()
    {
        var (svc, handler, _, sched, clientId) = Create(status: HttpStatusCode.OK, clientIdOverride: "clienta");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess"); // use named args to pick client overload
        var diag = FetchDiagForClient(clientId);
        Assert.IsNotNull(handler.LastRequest, "HTTP request should be issued on success path");
        Assert.AreEqual(0, sched.Scheduled.Count, "No retry should be scheduled on success");
        Assert.IsTrue(sched.AttemptOutcomes.Any(o => o.success), "Attempt outcome success should be reported");
        Assert.IsTrue(diag.Any(l => l.Contains("dispatch.success")), "Diagnostics should contain dispatch.success");
        Assert.IsTrue(diag.Any(l => l.Contains("reported=success")), "Diagnostics should contain attempt success outcome. Diagnostics:\n" + string.Join("\n", diag));
    }

    [TestMethod]
    public async Task Failure_Status_Triggers_Retry_And_Diagnostics()
    {
        var (svc, handler, db, sched, clientId) = Create(status: HttpStatusCode.InternalServerError, clientIdOverride: "clientb");
        // Safety check: ensure client present
        Assert.IsTrue(db.Clients.AsNoTracking().Any(c => c.ClientId == clientId), "Precondition failed: client not in DB");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var all = BackChannelLogoutService.GetRecentDiagnostics();
        Assert.IsTrue(all.Length > 0, "Global diagnostics buffer is empty - Trace() not executing");
        var diag = FetchDiagForClient(clientId);
        bool hasPostBegin = diag.Any(l => l.Contains("http.post.begin"));
        bool hasFailure = diag.Any(l => l.Contains("dispatch.failure"));
        bool hasOutcome = diag.Any(l => l.Contains("attempt.outcome client="));
        bool hasRetry = diag.Any(l => l.Contains("retry.scheduled"));
        if (!hasPostBegin && !hasFailure)
        {
            Assert.Fail("Expected http.post.begin or dispatch.failure trace. FULL Diagnostics:\n" + string.Join("\n", diag));
        }
        Assert.IsTrue(hasOutcome, "Expected attempt outcome trace. FULL Diagnostics:\n" + string.Join("\n", diag));
        Assert.IsTrue(hasRetry, "Expected retry scheduling trace. FULL Diagnostics:\n" + string.Join("\n", diag));
        Assert.AreEqual(1, sched.Scheduled.Count, "Should schedule one retry for failure");
    }

    [TestMethod]
    public async Task Timeout_Schedules_Retry_With_Diagnostics()
    {
        var (svc, handler, _, sched, clientId) = Create(status: HttpStatusCode.OK, timeout: true, clientIdOverride: "clientc");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var diag = FetchDiagForClient(clientId);
        Assert.IsTrue(diag.Any(l => l.Contains("dispatch.timeout")), "Expected timeout diagnostic");
        Assert.IsTrue(diag.Any(l => l.Contains("reported=timeout")), "Expected timeout attempt outcome. Diagnostics:\n" + string.Join("\n", diag));
        Assert.IsTrue(diag.Any(l => l.Contains("retry.scheduled")), "Expected retry scheduled after timeout");
        Assert.AreEqual(1, sched.Scheduled.Count, "Timeout should schedule retry");
    }

    [TestMethod]
    public async Task Missing_Client_Diagnostics()
    {
        var (svc, handler, _, sched, clientId) = Create(withClient: false, clientIdOverride: "clientd");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var diag = FetchDiagForClient(clientId);
        Assert.IsTrue(diag.Any(l => l.Contains("client.lookup.miss")), "Expected client lookup miss trace");
        Assert.IsTrue(diag.Any(l => l.Contains("dispatch.skip.missing_client")), "Expected skip missing client trace");
        Assert.IsTrue(diag.Any(l => l.Contains("reported=missing_client")), "Expected missing client attempt outcome trace. Diagnostics:\n" + string.Join("\n", diag));
        Assert.AreEqual(0, sched.Scheduled.Count, "Missing client should not schedule retries");
    }
}
