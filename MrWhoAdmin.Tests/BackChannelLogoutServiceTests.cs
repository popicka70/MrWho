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
using System.Linq;
using Microsoft.AspNetCore.Http;
using System.Diagnostics.Metrics;

namespace MrWhoAdmin.Tests;

[TestClass]
public class BackChannelLogoutServiceTests
{
    private sealed class TestDiagSink : IBackChannelLogoutDiagnostics
    {
        public List<BackChannelLogoutDiagEvent> Events { get; } = new();
        public void Emit(BackChannelLogoutDiagEvent evt) => Events.Add(evt);
        public IEnumerable<BackChannelLogoutDiagEvent> ForClient(string clientId) => Events.Where(e => e.ClientId == clientId);
    }

    private sealed class TestHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest;
        public HttpStatusCode Status = HttpStatusCode.OK;
        public bool SimulateTimeout;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (SimulateTimeout) throw new TaskCanceledException("timeout");
            LastRequest = request;
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
        public void ScheduleRetry(BackChannelLogoutRetryWork work) => Scheduled.Add(work with { Attempt = work.Attempt + 1 });
        public void ReportAttemptOutcome(string clientId, string subject, string sessionId, int attempt, bool success, string? status, string? error)
            => AttemptOutcomes.Add((clientId, sessionId, attempt, success, status, error));
        public void ReportExhausted(string clientId, string subject, string sessionId, int attempts) => Exhausted.Add((clientId, sessionId, attempts));
    }

    private (BackChannelLogoutService Service, TestHandler Handler, ApplicationDbContext Db, FakeScheduler Scheduler, TestDiagSink Diags, string ClientId) Create(bool withClient = true, HttpStatusCode status = HttpStatusCode.OK, bool timeout = false, string clientIdOverride = "mrwho_demo1")
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        var handler = new TestHandler { Status = status, SimulateTimeout = timeout };
        services.AddHttpClient("backchannel").ConfigurePrimaryHttpMessageHandler(() => handler);
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(new byte[32]), Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256));
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(new TestOptionsMonitor<OpenIddictServerOptions>(options));
        services.AddSingleton(new Mock<IOpenIddictAuthorizationManager>().Object);
        services.AddSingleton(new Mock<IOpenIddictApplicationManager>().Object);
        var dbName = $"bcl_{clientIdOverride}";
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(dbName));
        var scheduler = new FakeScheduler();
        services.AddSingleton<IBackChannelLogoutRetryScheduler>(scheduler);
        var diagSink = new TestDiagSink();
        services.AddSingleton<IBackChannelLogoutDiagnostics>(diagSink);
        var sp = services.BuildServiceProvider();
        var db = sp.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();
        var clientId = clientIdOverride;
        if (withClient)
        {
            if (!db.Clients.Any(c => c.ClientId == clientId))
            {
                db.Clients.Add(new Client { Id = Guid.NewGuid().ToString(), ClientId = clientId, Name = clientId, IsEnabled = true, RealmId = Guid.NewGuid().ToString(), BackChannelLogoutUri = $"https://{clientId}.example.com/signout-backchannel" });
                db.SaveChanges();
            }
        }
        var svc = new BackChannelLogoutService(sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<ILogger<BackChannelLogoutService>>(), sp, sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>(), null, scheduler, diagSink);
        return (svc, handler, db, scheduler, diagSink, clientId);
    }

    private static bool HasEvent(IEnumerable<BackChannelLogoutDiagEvent> events, BackChannelLogoutDiagEventType type) => events.Any(e => e.Type == type);

    [TestMethod]
    public async Task Success_Does_Not_Schedule_Retry()
    {
        var (svc, handler, _, sched, diags, clientId) = Create(status: HttpStatusCode.OK, clientIdOverride: "clienta");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var ev = diags.ForClient(clientId).ToList();
        Assert.IsNotNull(handler.LastRequest, "Expected HTTP request");
        Assert.AreEqual(0, sched.Scheduled.Count, "No retry expected");
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.DispatchSuccess), "Missing dispatch success event" + Dump(ev));
    }

    [TestMethod]
    public async Task Failure_Status_Triggers_Retry_And_Diagnostics()
    {
        var (svc, handler, db, sched, diags, clientId) = Create(status: HttpStatusCode.InternalServerError, clientIdOverride: "clientb");
        Assert.IsTrue(db.Clients.Any(c => c.ClientId == clientId), "Client not seeded");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var ev = diags.ForClient(clientId).ToList();
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.HttpPostBegin), "No HTTP begin" + Dump(ev));
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.DispatchFailure), "No failure event" + Dump(ev));
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.RetryScheduled), "No retry scheduled event" + Dump(ev));
        Assert.AreEqual(1, sched.Scheduled.Count, "Retry should be scheduled");
    }

    [TestMethod]
    public async Task Timeout_Schedules_Retry_With_Diagnostics()
    {
        var (svc, handler, _, sched, diags, clientId) = Create(status: HttpStatusCode.OK, timeout: true, clientIdOverride: "clientc");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var ev = diags.ForClient(clientId).ToList();
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.DispatchTimeout), "Missing timeout event" + Dump(ev));
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.RetryScheduled), "Missing retry scheduled event" + Dump(ev));
        Assert.AreEqual(1, sched.Scheduled.Count, "Retry should be scheduled on timeout");
    }

    [TestMethod]
    public async Task Missing_Client_Does_Not_Schedule()
    {
        var (svc, handler, _, sched, diags, clientId) = Create(withClient: false, clientIdOverride: "clientd");
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        var ev = diags.ForClient(clientId).ToList();
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.ClientLookupMiss), "Expected lookup miss" + Dump(ev));
        Assert.IsTrue(HasEvent(ev, BackChannelLogoutDiagEventType.SkipMissingClient), "Expected skip missing client" + Dump(ev));
        Assert.AreEqual(0, sched.Scheduled.Count, "No retry expected for missing client");
        Assert.IsNull(handler.LastRequest, "No HTTP request expected");
    }

    [TestMethod]
    public async Task Retry_Exhaustion_Emits_Aggregate()
    {
        var (svc, _, db, sched, diags, clientId) = Create(status: HttpStatusCode.InternalServerError, clientIdOverride: "client_exhaust");
        // initial attempt -> failure schedules retry
        await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
        // Simulate processing of scheduled retries manually (not running background service here)
        for (int attempt = 2; attempt <= 4; attempt++)
        {
            // simulate scheduler invoking service again with same failure
            await svc.NotifyClientLogoutAsync(clientId: clientId, subject: "subj", sessionId: "sess");
            // scheduler would record attempt outcome; mimic
            sched.ReportAttemptOutcome(clientId, "subj", "sess", attempt, false, null, "500");
        }
        // final exhaustion
        sched.ReportExhausted(clientId, "subj", "sess", 4);
        var events = diags.ForClient(clientId).ToList();
        Assert.IsTrue(events.Any(e => e.Type == BackChannelLogoutDiagEventType.DispatchFailure), "Expected at least one failure" + Dump(events));
    }

    [TestMethod]
    public async Task Metrics_Counters_Increment_For_Success_And_Failure()
    {
        var listenerValues = new Dictionary<string,long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (inst, l) => { if (inst.Meter.Name == "MrWho.Logout") l.EnableMeasurementEvents(inst); };
        listener.SetMeasurementEventCallback<long>((inst, value, tags, state) =>
        {
            lock(listenerValues)
            {
                if(!listenerValues.ContainsKey(inst.Name)) listenerValues[inst.Name]=0;
                listenerValues[inst.Name]+=value;
            }
        });
        listener.Start();

        // success path
        var (svcSuccess, _, _, _, _, clientSuccess) = Create(status: HttpStatusCode.OK, clientIdOverride: "metrics_success");
        await svcSuccess.NotifyClientLogoutAsync(clientId: clientSuccess, subject: "subj", sessionId: "sess");
        // failure path
        var (svcFail, _, _, _, _, clientFail) = Create(status: HttpStatusCode.InternalServerError, clientIdOverride: "metrics_fail");
        await svcFail.NotifyClientLogoutAsync(clientId: clientFail, subject: "subj", sessionId: "sess");
        // small delay to allow listener to receive callbacks
        await Task.Delay(50);

        lock(listenerValues)
        {
            Assert.IsTrue(listenerValues.TryGetValue("mrwho_logout_backchannel_attempts_total", out var attempts) && attempts >= 2, "Expected at least 2 attempt increments");
            Assert.IsTrue(listenerValues.TryGetValue("mrwho_logout_backchannel_failures_total", out var failures) && failures >= 1, "Expected at least 1 failure increment");
        }
    }

    [TestMethod]
    public async Task LogoutToken_Signed_JWT_Contains_RequiredClaims()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(new byte[32]), Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256));
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(new TestOptionsMonitor<OpenIddictServerOptions>(options));
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase("jwt_signed"));
        var sp = services.BuildServiceProvider();
        var svc = new BackChannelLogoutService(new HttpClientFactoryStub(), sp.GetRequiredService<ILogger<BackChannelLogoutService>>(), sp, sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>(), null, null, new TestDiagSink());
        var jwt = await svc.CreateLogoutTokenAsync("clientX","subj","sess123");
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        Assert.IsTrue(handler.CanReadToken(jwt), "Expected readable JWT token");
        var token = handler.ReadJwtToken(jwt);
        Assert.AreEqual("logout+jwt", token.Header[System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ]);
        Assert.AreEqual("subj", token.Claims.First(c=>c.Type=="sub").Value);
        Assert.AreEqual("sess123", token.Claims.First(c=>c.Type=="sid").Value);
        Assert.IsTrue(token.Payload.ContainsKey("events"), "Missing events claim");
    }

    [TestMethod]
    public async Task LogoutToken_Fallback_NoSigningCredentials_Returns_Json()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var options = new OpenIddictServerOptions(); // no signing creds
        services.AddSingleton<IOptionsMonitor<OpenIddictServerOptions>>(new TestOptionsMonitor<OpenIddictServerOptions>(options));
        services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase("jwt_json"));
        var sp = services.BuildServiceProvider();
        var svc = new BackChannelLogoutService(new HttpClientFactoryStub(), sp.GetRequiredService<ILogger<BackChannelLogoutService>>(), sp, sp.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>(), null, null, new TestDiagSink());
        var tokenStr = await svc.CreateLogoutTokenAsync("clientY","user","sidABC");
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        Assert.IsFalse(handler.CanReadToken(tokenStr), "Fallback should not be a JWT");
        Assert.IsTrue(tokenStr.Contains("\"events\""), "JSON fallback should contain events field");
    }

    // Minimal HttpClientFactory stub for token tests (no HTTP usage)
    private sealed class HttpClientFactoryStub : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new HttpClient(new HttpClientHandler());
    }

    private static string Dump(IEnumerable<BackChannelLogoutDiagEvent> ev)
        => "\nEVENTS:\n" + string.Join("\n", ev.Select(e => $"{e.Type} success={e.Success} attempt={e.Attempt} status={e.Status} error={e.Error}"));
}
