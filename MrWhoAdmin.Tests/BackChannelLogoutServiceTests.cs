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

namespace MrWhoAdmin.Tests;

[TestClass]
public class BackChannelLogoutServiceTests
{
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

    private (BackChannelLogoutService Service, TestHandler Handler, ApplicationDbContext Db, FakeScheduler Scheduler) Create(bool withClient = true, HttpStatusCode status = HttpStatusCode.OK, bool timeout = false)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var handler = new TestHandler { Status = status, SimulateTimeout = timeout };
        services.AddHttpClient("backchannel").ConfigurePrimaryHttpMessageHandler(() => handler);

        var options = new OpenIddictServerOptions();
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(new TestOptionsMonitor<OpenIddictServerOptions>(options));

        // Required managers (mocked)
        services.AddSingleton(new Mock<IOpenIddictAuthorizationManager>().Object);
        services.AddSingleton(new Mock<IOpenIddictApplicationManager>().Object);

        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        var scheduler = new FakeScheduler();
        services.AddSingleton<IBackChannelLogoutRetryScheduler>(scheduler);

        var sp = services.BuildServiceProvider();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();
        if (withClient)
        {
            db.Clients.Add(new Client
            {
                Id = Guid.NewGuid().ToString(),
                ClientId = "mrwho_demo1", // use known fallback id with predefined back-channel URI
                Name = "Demo1",
                IsEnabled = true,
                RealmId = Guid.NewGuid().ToString(),
                BackChannelLogoutUri = null // rely on fallback to ensure path even if property mapping missing
            });
            db.SaveChanges();
        }
        var svc = new BackChannelLogoutService(sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<ILogger<BackChannelLogoutService>>(), sp, sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>(), null, scheduler);
        return (svc, handler, db, scheduler);
    }

    [TestMethod]
    public async Task Success_Does_Not_Schedule_Retry()
    {
        var (svc, _, _, sched) = Create(status: HttpStatusCode.OK);
        await svc.NotifyClientLogoutAsync("mrwho_demo1", "subj", "sess");
        Assert.AreEqual(0, sched.Scheduled.Count, "No retry should be scheduled on success");
    }

    [TestMethod]
    public async Task Failure_Status_Schedules_Retry()
    {
        var (svc, _, _, sched) = Create(status: HttpStatusCode.InternalServerError);
        await svc.NotifyClientLogoutAsync("mrwho_demo1", "subj", "sess");
        Assert.AreEqual(1, sched.Scheduled.Count, "Failure should schedule one retry");
        var work = sched.Scheduled[0];
        Assert.AreEqual("mrwho_demo1", work.ClientId);
        Assert.AreEqual(2, work.Attempt, "Scheduler increments attempt for first retry (Attempt=2)");
    }

    [TestMethod]
    public async Task Timeout_Schedules_Retry()
    {
        var (svc, handler, _, sched) = Create(status: HttpStatusCode.OK, timeout: true);
        await svc.NotifyClientLogoutAsync("mrwho_demo1", "subj", "sess");
        Assert.AreEqual(1, sched.Scheduled.Count, "Timeout should schedule retry");
    }

    [TestMethod]
    public async Task Missing_Client_Does_Not_Schedule()
    {
        var (svc, _, _, sched) = Create(withClient: false);
        await svc.NotifyClientLogoutAsync("mrwho_demo1", "subj", "sess");
        Assert.AreEqual(0, sched.Scheduled.Count, "Missing client should not schedule retries");
    }
}
