using Microsoft.AspNetCore.Authentication;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.Metrics;

namespace MrWho.Services;

public enum BackChannelLogoutDiagEventType { Start, ClientLookupHit, ClientLookupMiss, SkipMissingClient, SkipNoUri, TokenBuild, HttpPostBegin, HttpPostEnd, DispatchSuccess, DispatchFailure, DispatchTimeout, DispatchError, DispatchUnhandled, AttemptOutcome, RetryScheduled }
public sealed record BackChannelLogoutDiagEvent(BackChannelLogoutDiagEventType Type, string ClientId, bool? Success = null, int? Attempt = null, string? Status = null, string? Error = null, double? DurationMs = null);
public interface IBackChannelLogoutDiagnostics { void Emit(BackChannelLogoutDiagEvent evt); }
public sealed class NoOpBackChannelLogoutDiagnostics : IBackChannelLogoutDiagnostics { public static readonly NoOpBackChannelLogoutDiagnostics Instance = new(); public void Emit(BackChannelLogoutDiagEvent evt) { } }

public interface IBackChannelLogoutService
{
    Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId);
    Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null);
    Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId);
}

public class BackChannelLogoutService : IBackChannelLogoutService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<BackChannelLogoutService> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly ISecurityAuditWriter? _audit;
    private readonly IBackChannelLogoutRetryScheduler? _retryScheduler;
    private readonly IBackChannelLogoutDiagnostics _diagnostics;

    private static readonly Meter _meter = new("MrWho.Logout", "1.0.0");
    private static readonly Counter<long> _attemptsCounter = _meter.CreateCounter<long>("mrwho_logout_backchannel_attempts_total");
    private static readonly Counter<long> _failuresCounter = _meter.CreateCounter<long>("mrwho_logout_backchannel_failures_total");

    public BackChannelLogoutService(
        IHttpClientFactory httpClientFactory,
        ILogger<BackChannelLogoutService> logger,
        IServiceProvider serviceProvider,
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        ISecurityAuditWriter? audit = null,
        IBackChannelLogoutRetryScheduler? retryScheduler = null,
        IBackChannelLogoutDiagnostics? diagnostics = null)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _serviceProvider = serviceProvider;
        _serverOptions = serverOptions;
        _audit = audit;
        _retryScheduler = retryScheduler;
        _diagnostics = diagnostics ?? NoOpBackChannelLogoutDiagnostics.Instance;
    }

    public async Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId)
    {
        try
        {
            Models.Client? clientToNotify;
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
                var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

                var authorization = await authorizationManager.FindByIdAsync(authorizationId);
                if (authorization == null) { return; }
                var applicationId = await authorizationManager.GetApplicationIdAsync(authorization);
                if (string.IsNullOrEmpty(applicationId)) { return; }
                var application = await applicationManager.FindByIdAsync(applicationId);
                if (application == null) { return; }
                var clientId = await applicationManager.GetClientIdAsync(application);
                if (string.IsNullOrEmpty(clientId)) { return; }

                clientToNotify = await context.Clients.FirstOrDefaultAsync(c => c.ClientId == clientId) ?? new Models.Client { ClientId = clientId, IsEnabled = true };
            }
            await NotifyClientLogoutInternalAsync(clientToNotify.ClientId, subject, sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending back-channel logout notifications for authorization {AuthorizationId}", authorizationId);
        }
    }

    public async Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
        => await NotifyClientLogoutInternalAsync(clientId, subject, sessionId, logoutToken);

    private async Task NotifyClientLogoutInternalAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
    {
        _diagnostics.Emit(new(BackChannelLogoutDiagEventType.Start, clientId));
        _attemptsCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
        try
        {
            Models.Client? client;
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                client = await context.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
                if (client == null)
                {
                    var ignored = await context.Clients.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
                    if (ignored != null) client = ignored;
                }
                _diagnostics.Emit(new(client == null ? BackChannelLogoutDiagEventType.ClientLookupMiss : BackChannelLogoutDiagEventType.ClientLookupHit, clientId, Success: client != null));
            }

            if (client == null)
            {
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, "client_missing");
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.SkipMissingClient, clientId, Success: false, Attempt: 1, Error: "client_missing"));
                _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                return;
            }

            var logoutUri = GetBackChannelLogoutUri(client);
            if (string.IsNullOrEmpty(logoutUri))
            {
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, true, "skipped", null);
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.SkipNoUri, clientId, Success: true, Attempt: 1, Status: "skipped"));
                return;
            }

            if (string.IsNullOrEmpty(logoutToken))
            {
                logoutToken = await CreateLogoutTokenAsync(clientId, subject, sessionId);
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.TokenBuild, clientId));
            }

            HttpClient httpClient;
            try { httpClient = _httpClientFactory.CreateClient("backchannel"); }
            catch { httpClient = _httpClientFactory.CreateClient(); }
            httpClient.Timeout = TimeSpan.FromSeconds(10);

            var formData = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("logout_token", logoutToken!) });

            var start = DateTime.UtcNow;
            HttpResponseMessage? response = null;
            try
            {
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.HttpPostBegin, clientId));
                response = await httpClient.PostAsync(logoutUri, formData);
                var elapsed = (DateTime.UtcNow - start).TotalMilliseconds;
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.HttpPostEnd, clientId, DurationMs: elapsed, Status: ((int)response.StatusCode).ToString()));
                if (response.IsSuccessStatusCode)
                {
                    _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, true, ((int)response.StatusCode).ToString(), null);
                    _diagnostics.Emit(new(BackChannelLogoutDiagEventType.DispatchSuccess, clientId, Success: true, Attempt: 1, Status: ((int)response.StatusCode).ToString(), DurationMs: elapsed));
                }
                else
                {
                    _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                    _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, ((int)response.StatusCode).ToString(), null);
                    _diagnostics.Emit(new(BackChannelLogoutDiagEventType.DispatchFailure, clientId, Success: false, Attempt: 1, Status: ((int)response.StatusCode).ToString()));
                    if (_retryScheduler != null)
                    {
                        _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                        _diagnostics.Emit(new(BackChannelLogoutDiagEventType.RetryScheduled, clientId, Success: false, Attempt: 2));
                    }
                }
            }
            catch (TaskCanceledException)
            {
                _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, "timeout");
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.DispatchTimeout, clientId, Success: false, Attempt: 1, Error: "timeout"));
                if (_retryScheduler != null)
                {
                    _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                    _diagnostics.Emit(new(BackChannelLogoutDiagEventType.RetryScheduled, clientId, Success: false, Attempt: 2));
                }
            }
            catch (Exception ex)
            {
                _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, ex.GetType().Name);
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.DispatchError, clientId, Success: false, Attempt: 1, Error: ex.GetType().Name));
                if (_retryScheduler != null)
                {
                    _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                    _diagnostics.Emit(new(BackChannelLogoutDiagEventType.RetryScheduled, clientId, Success: false, Attempt: 2));
                }
            }
            finally { response?.Dispose(); }
        }
        catch (Exception exOuter)
        {
            _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
            _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, exOuter.GetType().Name);
            _diagnostics.Emit(new(BackChannelLogoutDiagEventType.DispatchUnhandled, clientId, Success: false, Attempt: 1, Error: exOuter.GetType().Name));
            if (_retryScheduler != null)
            {
                _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                _diagnostics.Emit(new(BackChannelLogoutDiagEventType.RetryScheduled, clientId, Success: false, Attempt: 2));
            }
        }
    }

    public Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId)
    {
        try
        {
            var options = _serverOptions.CurrentValue;
            var issuer = options.Issuer?.AbsoluteUri?.TrimEnd('/') ?? "https://localhost:7113";
            var signing = options.SigningCredentials.FirstOrDefault();
            if (signing is null)
            {
                var fallback = new { iss = issuer, sub = subject, aud = clientId, iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), jti = Guid.NewGuid().ToString(), events = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() }, sid = sessionId };
                return Task.FromResult(JsonSerializer.Serialize(fallback));
            }
            var now = DateTimeOffset.UtcNow;
            var claims = new List<System.Security.Claims.Claim> { new("sub", subject), new("sid", sessionId), new("jti", Guid.NewGuid().ToString()) };
            var token = new JwtSecurityToken(issuer: issuer, audience: clientId, claims: claims, notBefore: now.UtcDateTime, expires: now.AddMinutes(2).UtcDateTime, signingCredentials: signing);
            token.Payload["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() };
            token.Payload["iat"] = now.ToUnixTimeSeconds();
            token.Header[JwtHeaderParameterNames.Typ] = "logout+jwt";
            var handler = new JwtSecurityTokenHandler();
            return Task.FromResult(handler.WriteToken(token));
        }
        catch
        {
            var fallback = new { iss = "https://localhost:7113", sub = subject, aud = clientId, iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), jti = Guid.NewGuid().ToString(), events = new Dictionary<string, object> { ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>() }, sid = sessionId };
            return Task.FromResult(JsonSerializer.Serialize(fallback));
        }
    }

    private string? GetBackChannelLogoutUri(Models.Client client)
    {
        if (!string.IsNullOrWhiteSpace(client.BackChannelLogoutUri)) return client.BackChannelLogoutUri;
        return client.ClientId switch { "mrwho_demo1" => "https://localhost:7037/signout-backchannel", "mrwho_admin_web" => "https://localhost:7257/signout-backchannel", _ => null };
    }
}