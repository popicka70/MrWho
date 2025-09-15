using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared;
using MrWho.Services; // for ParMetrics

namespace MrWho.Controllers;

/// <summary>
/// Minimal PAR (Pushed Authorization Request) endpoint (PJ48 initial implementation).
/// Accepts standard authorization request parameters plus optional signed request object ("request").
/// Stores parameters for short-lived reuse and returns a request_uri referencing persisted data.
/// JAR validation deferred to existing early extract handler at authorization stage.
/// </summary>
[AllowAnonymous]
[ApiController]
[Route("connect/par")] // RFC 9126 endpoint
public class PushedAuthorizationController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<PushedAuthorizationController> _logger;

    public PushedAuthorizationController(ApplicationDbContext db, ILogger<PushedAuthorizationController> logger)
    { _db = db; _logger = logger; }

    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Push(CancellationToken ct)
    {
        if (!Request.HasFormContentType)
        {
            return BadRequest(new { error = "invalid_request", error_description = "Form URL encoded body required" });
        }
        var form = await Request.ReadFormAsync(ct);

        // Client authentication (basic or body) – simplified
        string? clientId = form["client_id"].ToString();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id missing" });
        }

        string? providedSecret = null;
        // Basic auth
        if (Request.Headers.TryGetValue("Authorization", out var auth) && auth.ToString().StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var raw = auth.ToString()[6..].Trim();
                var bytes = Convert.FromBase64String(raw);
                var decoded = Encoding.UTF8.GetString(bytes);
                var parts = decoded.Split(':', 2);
                if (parts.Length == 2 && string.Equals(parts[0], clientId, StringComparison.Ordinal))
                {
                    providedSecret = parts[1];
                }
            }
            catch { }
        }
        providedSecret ??= form["client_secret"].ToString();

        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId, ct);
        if (client == null || !client.IsEnabled)
        {
            return Unauthorized(new { error = "invalid_client", error_description = "unknown client" });
        }
        if ((client.ClientType == ClientType.Confidential || client.ClientType == ClientType.Machine || client.RequireClientSecret) && string.IsNullOrEmpty(providedSecret))
        {
            return Unauthorized(new { error = "invalid_client", error_description = "missing client secret" });
        }
        if (!string.IsNullOrEmpty(providedSecret) && client.ClientSecret is not null && !string.Equals(client.ClientSecret, providedSecret, StringComparison.Ordinal))
        {
            // NOTE: future: support hashed secrets / secret history
            return Unauthorized(new { error = "invalid_client", error_description = "invalid client secret" });
        }

        // PAR mode check
        var parMode = client.ParMode ?? PushedAuthorizationMode.Disabled;
        if (parMode == PushedAuthorizationMode.Disabled)
        {
            return BadRequest(new { error = "invalid_request", error_description = "PAR disabled for this client" });
        }

        // Collect parameters (excluding secrets) into dictionary (string->string)
        var paramDict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in form)
        {
            if (kv.Key.Equals("client_secret", StringComparison.OrdinalIgnoreCase)) continue;
            paramDict[kv.Key] = kv.Value.ToString();
        }

        // Canonical JSON (sorted keys) for hashing and storage
        var ordered = paramDict.OrderBy(k => k.Key, StringComparer.Ordinal).ToDictionary(k => k.Key, v => v.Value, StringComparer.Ordinal);
        var json = JsonSerializer.Serialize(ordered, new JsonSerializerOptions { WriteIndented = false });
        string hash;
        using (var sha = SHA256.Create())
        {
            hash = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(json)));
        }

        // Attempt reuse: same client + same hash + unexpired
        var now = DateTime.UtcNow;
        var reuse = await _db.PushedAuthorizationRequests.AsNoTracking()
            .Where(p => p.ClientId == clientId && p.ParametersHash == hash && p.ExpiresAt > now)
            .OrderByDescending(p => p.ExpiresAt)
            .FirstOrDefaultAsync(ct);
        if (reuse != null)
        {
            var remaining = (int)Math.Max(0, (reuse.ExpiresAt - now).TotalSeconds);
            _logger.LogDebug("[PAR] Reused request_uri for client {ClientId} hash {Hash} remaining={Remaining}s", clientId, hash[..16], remaining);
            ParMetrics.RecordParPush(clientId, reused: true); // METRIC
            return Ok(new { request_uri = reuse.RequestUri, expires_in = remaining, reused = true });
        }

        // Create new stored request
        var id = Guid.NewGuid().ToString("n");
        var requestUri = $"urn:ietf:params:oauth:request_uri:{id}";
        var entity = new PushedAuthorizationRequest
        {
            Id = id,
            RequestUri = requestUri,
            ClientId = clientId,
            ParametersJson = json,
            ParametersHash = hash,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(90) // default short lifetime
        };
        _db.PushedAuthorizationRequests.Add(entity);
        try
        {
            await _db.SaveChangesAsync(ct);
            ParMetrics.RecordParPush(clientId, reused: false); // METRIC new
        }
        catch (DbUpdateException ex)
        {
            _logger.LogWarning(ex, "[PAR] Failed persisting pushed request for client {ClientId}");
            return StatusCode(500, new { error = "server_error", error_description = "failed to persist pushed request" });
        }

        _logger.LogDebug("[PAR] Stored request_uri {RequestUri} (client {ClientId}, hash {Hash}, exp +90s)", requestUri, clientId, hash[..16]);
        return Ok(new { request_uri = requestUri, expires_in = 90, reused = false });
    }
}
