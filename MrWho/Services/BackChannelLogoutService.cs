using Microsoft.AspNetCore.Authentication;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using MrWho.Services; // add for ISecurityAuditWriter
using MrWho.Services; // ensure retry scheduler interfaces
using System.Diagnostics.Metrics; // metrics

namespace MrWho.Services;

/// <summary>
/// Service for handling back-channel logout notifications to client applications
/// </summary>
public interface IBackChannelLogoutService
{
    /// <summary>
    /// Sends back-channel logout notifications to all clients for a user session
    /// </summary>
    Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId);

    /// <summary>
    /// Sends back-channel logout notification to a specific client
    /// </summary>
    Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null);

    /// <summary>
    /// Creates a logout token for back-channel logout
    /// </summary>
    Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId);
}

public class BackChannelLogoutService : IBackChannelLogoutService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<BackChannelLogoutService> _logger;
    private readonly IServiceProvider _serviceProvider; // Changed from direct DbContext injection
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;
    private readonly ISecurityAuditWriter? _audit; // optional audit writer
    private readonly IBackChannelLogoutRetryScheduler? _retryScheduler;

    // Metrics (placeholder counters). These are lightweight and safe to be static singletons.
    private static readonly Meter _meter = new("MrWho.Logout", "1.0.0");
    private static readonly Counter<long> _attemptsCounter = _meter.CreateCounter<long>("mrwho_logout_backchannel_attempts_total");
    private static readonly Counter<long> _failuresCounter = _meter.CreateCounter<long>("mrwho_logout_backchannel_failures_total");

    // DIAGNOSTICS: simple in-memory ring buffer (not thread-safe perfection but adequate for test visibility if exposed later)
    private static readonly int DiagCapacity = 200;
    private static readonly List<string> _diag = new();
    private static int _traceCount = 0; // diagnostic counter
    private static void Trace(string msg)
    {
        Interlocked.Increment(ref _traceCount);
        lock (_diag)
        {
            if (_diag.Count >= DiagCapacity) _diag.RemoveAt(0);
            _diag.Add(DateTime.UtcNow.ToString("HH:mm:ss.fff") + " | " + msg);
        }
    }
    public static string[] GetRecentDiagnostics() { lock (_diag) return _diag.ToArray(); }
    public static void ClearDiagnostics() { lock (_diag) _diag.Clear(); Interlocked.Exchange(ref _traceCount, 0); }
    public static int GetTraceCount() => Volatile.Read(ref _traceCount);

    public BackChannelLogoutService(
        IHttpClientFactory httpClientFactory,
        ILogger<BackChannelLogoutService> logger,
        IServiceProvider serviceProvider, // Use service provider to create scoped contexts
        IOptionsMonitor<OpenIddictServerOptions> serverOptions,
        ISecurityAuditWriter? audit = null,
        IBackChannelLogoutRetryScheduler? retryScheduler = null)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _serviceProvider = serviceProvider;
        _serverOptions = serverOptions;
        _audit = audit;
        _retryScheduler = retryScheduler;
    }

    public async Task NotifyClientLogoutAsync(string authorizationId, string subject, string sessionId)
    {
        Trace($"notify.authId.start authId={authorizationId} subj={subject} sid={sessionId}");
        try
        {
            // Get the specific client for this authorization
            Models.Client? clientToNotify;
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
                var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                
                // Find the authorization and get its application
                var authorization = await authorizationManager.FindByIdAsync(authorizationId);
                if (authorization == null)
                {
                    _logger.LogWarning("Authorization {AuthorizationId} not found for logout notification", authorizationId);
                    return;
                }
                
                var applicationId = await authorizationManager.GetApplicationIdAsync(authorization);
                if (string.IsNullOrEmpty(applicationId))
                {
                    _logger.LogWarning("Authorization {AuthorizationId} has no associated application", authorizationId);
                    return;
                }
                
                var application = await applicationManager.FindByIdAsync(applicationId);
                if (application == null)
                {
                    _logger.LogWarning("Application {ApplicationId} not found for authorization {AuthorizationId}", applicationId, authorizationId);
                    return;
                }
                
                var clientId = await applicationManager.GetClientIdAsync(application);
                if (string.IsNullOrEmpty(clientId))
                {
                    _logger.LogWarning("Application {ApplicationId} has no client ID", applicationId);
                    return;
                }
                
                // Get the client from our database if it exists
                clientToNotify = await context.Clients
                    .FirstOrDefaultAsync(c => c.ClientId == clientId);
                
                // If not in our database, create a temporary client object for notification
                if (clientToNotify == null)
                {
                    clientToNotify = new Models.Client
                    {
                        ClientId = clientId,
                        IsEnabled = true // Assume enabled for OpenIddict clients
                    };
                }
            }

            // Send notification to the specific client
            await NotifyClientLogoutInternalAsync(clientToNotify.ClientId, subject, sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending back-channel logout notifications for authorization {AuthorizationId}", authorizationId);
        }
    }

    public async Task NotifyClientLogoutAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
    {
        Trace($"notify.client.start client={clientId} subj={subject} sid={sessionId} tokenSupplied={(logoutToken!=null)}");
        await NotifyClientLogoutInternalAsync(clientId, subject, sessionId, logoutToken);
    }

    /// <summary>
    /// Internal method that creates its own DbContext scope for thread safety
    /// </summary>
    private async Task NotifyClientLogoutInternalAsync(string clientId, string subject, string sessionId, string? logoutToken = null)
    {
        Trace($"dispatch.start client={clientId} subj={subject} sid={sessionId} tokenSupplied={(logoutToken!=null)}");
        // Count every dispatch attempt (attempt number may be >1 when invoked by retry scheduler; scheduler records granular attempt audits)
        _attemptsCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
        try
        {
            Models.Client? client;
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                client = await context.Clients
                    .AsNoTracking()
                    .FirstOrDefaultAsync(c => c.ClientId == clientId);
                if (client == null)
                {
                    // Fallback ignoring global query filters (e.g., realm/soft delete) mainly for tests/diagnostics
                    var ignored = await context.Clients
                        .IgnoreQueryFilters()
                        .AsNoTracking()
                        .FirstOrDefaultAsync(c => c.ClientId == clientId);
                    if (ignored != null)
                    {
                        client = ignored;
                        Trace($"client.lookup.hit_ignore_filters client={clientId} hasUri={(string.IsNullOrWhiteSpace(client.BackChannelLogoutUri)?"false":"true")}");
                    }
                }
                Trace(client == null
                    ? $"client.lookup.miss client={clientId}"
                    : $"client.lookup.hit client={clientId} hasUri={(string.IsNullOrWhiteSpace(client.BackChannelLogoutUri)?"false":"true")} uri='{client.BackChannelLogoutUri}'");
            }

            if (client == null)
            {
                _logger.LogWarning("Client {ClientId} not found for logout notification", clientId);
                Trace($"dispatch.skip.missing_client client={clientId}");
                try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.skip_client_missing", new { clientId }, "warn", actorClientId: clientId); } catch { }
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, "client_missing");
                Trace($"attempt.outcome client={clientId} reported=missing_client schedulerPresent={_retryScheduler!=null}");
                return;
            }

            var logoutUri = GetBackChannelLogoutUri(client);
            if (string.IsNullOrEmpty(logoutUri))
            {
                _logger.LogDebug("No back-channel logout URI configured for client {ClientId}", clientId);
                Trace($"dispatch.skip.no_uri client={clientId}");
                try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.skip_no_uri", new { clientId }, "info", actorClientId: clientId); } catch { }
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, success: true, status: "skipped", error: null);
                Trace($"attempt.outcome client={clientId} reported=skipped schedulerPresent={_retryScheduler!=null}");
                return;
            }

            if (string.IsNullOrEmpty(logoutToken))
            {
                Trace($"token.build client={clientId}");
                logoutToken = await CreateLogoutTokenAsync(clientId, subject, sessionId);
            }

            HttpClient httpClient;
            try { httpClient = _httpClientFactory.CreateClient("backchannel"); Trace($"http.client.named=backchannel client={clientId}"); }
            catch { httpClient = _httpClientFactory.CreateClient(); Trace($"http.client.default client={clientId}"); }
            httpClient.Timeout = TimeSpan.FromSeconds(10);

            var formData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("logout_token", logoutToken!)
            });

            var start = DateTime.UtcNow;
            HttpResponseMessage? response = null;
            try
            {
                Trace($"http.post.begin client={clientId} uri='{logoutUri}'");
                response = await httpClient.PostAsync(logoutUri, formData);
                Trace($"http.post.end client={clientId} status={(int)response.StatusCode}");
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Back-channel logout notification sent successfully to client {ClientId}", clientId);
                    Trace($"dispatch.success client={clientId} status={(int)response.StatusCode}");
                    try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.dispatch.success", new { clientId, uri = logoutUri, ms = (DateTime.UtcNow-start).TotalMilliseconds, status = (int)response.StatusCode }, "info", actorClientId: clientId); } catch { }
                    _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, true, ((int)response.StatusCode).ToString(), null);
                    Trace($"attempt.outcome client={clientId} reported=success schedulerPresent={_retryScheduler!=null}");
                }
                else
                {
                    _logger.LogWarning("Back-channel logout notification failed for client {ClientId} with status {StatusCode}", clientId, response.StatusCode);
                    Trace($"dispatch.failure client={clientId} status={(int)response.StatusCode}");
                    try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.dispatch.failure", new { clientId, uri = logoutUri, status = (int)response.StatusCode }, "warn", actorClientId: clientId); } catch { }
                    _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                    _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, ((int)response.StatusCode).ToString(), null);
                    Trace($"attempt.outcome client={clientId} reported=failure schedulerPresent={_retryScheduler!=null}");
                    if (_retryScheduler != null)
                    {
                        _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                        Trace($"retry.scheduled client={clientId} nextAttempt=2");
                    }
                    else
                    {
                        Trace($"retry.scheduler.null client={clientId} - not scheduled");
                    }
                }
            }
            catch (TaskCanceledException tex)
            {
                _logger.LogWarning(tex, "Back-channel logout notification timeout for client {ClientId}", clientId);
                Trace($"dispatch.timeout client={clientId}");
                try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.dispatch.timeout", new { clientId, uri = logoutUri }, "warn", actorClientId: clientId); } catch { }
                _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, "timeout");
                Trace($"attempt.outcome client={clientId} reported=timeout schedulerPresent={_retryScheduler!=null}");
                if (_retryScheduler != null)
                {
                    _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                    Trace($"retry.scheduled client={clientId} after timeout nextAttempt=2");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending back-channel logout notification to client {ClientId}");
                Trace($"dispatch.error client={clientId} ex={ex.GetType().Name}");
                try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.dispatch.error", new { clientId, uri = logoutUri, ex = ex.Message }, "error", actorClientId: clientId); } catch { }
                _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
                _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, ex.GetType().Name);
                Trace($"attempt.outcome client={clientId} reported=error schedulerPresent={_retryScheduler!=null}");
                if (_retryScheduler != null)
                {
                    _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                    Trace($"retry.scheduled client={clientId} after error nextAttempt=2");
                }
            }
            finally
            {
                response?.Dispose();
            }
        }
        catch (Exception exOuter)
        {
            _logger.LogError(exOuter, "Unhandled error in back-channel logout dispatch for client {ClientId}", clientId);
            Trace($"dispatch.unhandled client={clientId} ex={exOuter.GetType().Name}");
            try { if (_audit != null) await _audit.WriteAsync("logout", "backchannel.dispatch.unhandled", new { clientId, ex = exOuter.Message }, "error", actorClientId: clientId); } catch { }
            _failuresCounter.Add(1, KeyValuePair.Create<string, object?>("client_id", clientId));
            _retryScheduler?.ReportAttemptOutcome(clientId, subject, sessionId, 1, false, null, exOuter.GetType().Name);
            Trace($"attempt.outcome client={clientId} reported=unhandled schedulerPresent={_retryScheduler!=null}");
            if (_retryScheduler != null)
            {
                _retryScheduler.ScheduleRetry(new BackChannelLogoutRetryWork(clientId, subject, sessionId));
                Trace($"retry.scheduled client={clientId} after unhandled nextAttempt=2");
            }
        }
    }

    public Task<string> CreateLogoutTokenAsync(string clientId, string subject, string sessionId)
    {
        try
        {
            var options = _serverOptions.CurrentValue;
            var issuer = options.Issuer?.AbsoluteUri?.TrimEnd('/') ?? string.Empty;

            if (string.IsNullOrEmpty(issuer))
            {
                _logger.LogWarning("OpenIddict issuer is not configured. Using fallback localhost issuer for logout_token.");
                issuer = "https://localhost:7113";
            }

            // Pick first signing credentials
            var signing = options.SigningCredentials.FirstOrDefault();
            if (signing is null)
            {
                _logger.LogWarning("No OpenIddict signing credentials configured. Back-channel logout_token cannot be signed.");
                // As a fallback, return the previous JSON payload to avoid breaking clients in dev
                var fallback = new
                {
                    iss = issuer,
                    sub = subject,
                    aud = clientId,
                    iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    jti = Guid.NewGuid().ToString(),
                    events = new Dictionary<string, object>
                    {
                        ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>()
                    },
                    sid = sessionId
                };
                return Task.FromResult(JsonSerializer.Serialize(fallback));
            }

            var now = DateTimeOffset.UtcNow;

            var claims = new List<System.Security.Claims.Claim>
            {
                new("sub", subject),
                new("sid", sessionId),
                new("jti", Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: clientId,
                claims: claims,
                notBefore: now.UtcDateTime,
                expires: now.AddMinutes(2).UtcDateTime, // short-lived
                signingCredentials: signing
            );

            // Set required extra payload members
            token.Payload["events"] = new Dictionary<string, object>
            {
                ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>()
            };
            token.Payload["iat"] = now.ToUnixTimeSeconds();

            // Set header typ to logout+jwt
            token.Header[JwtHeaderParameterNames.Typ] = "logout+jwt";

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);
            return Task.FromResult(jwt);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create spec-compliant logout_token. Falling back to JSON payload.");
            var fallback = new
            {
                iss = "https://localhost:7113",
                sub = subject,
                aud = clientId,
                iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                jti = Guid.NewGuid().ToString(),
                events = new Dictionary<string, object>
                {
                    ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>()
                },
                sid = sessionId
            };
            return Task.FromResult(JsonSerializer.Serialize(fallback));
        }
    }

    /// <summary>
    /// Gets clients for logout notification using the provided context
    /// </summary>
    private async Task<List<Models.Client>> GetClientsForLogoutNotificationAsync(ApplicationDbContext context, string subject)
    {
        // Get all clients that support back-channel logout
        return await context.Clients
            .Where(c => c.IsEnabled)
            .ToListAsync();
    }

    private string? GetBackChannelLogoutUri(Models.Client client)
    {
        // Prefer the configured BackChannelLogoutUri on the client
        if (!string.IsNullOrWhiteSpace(client.BackChannelLogoutUri))
        {
            return client.BackChannelLogoutUri;
        }

        // Fallbacks for known demo clients (dev only)
        return client.ClientId switch
        {
            "mrwho_demo1" => "https://localhost:7037/signout-backchannel",
            "mrwho_admin_web" => "https://localhost:7257/signout-backchannel",
            _ => null
        };
    }
}