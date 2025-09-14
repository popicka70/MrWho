using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting; // added
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using MrWho.Data;
using MrWho.Models;

namespace MrWho.Controllers;

[Route("connect")] // align with OIDC base path
public class DeviceAuthorizationController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<DeviceAuthorizationController> _logger;

    public DeviceAuthorizationController(ApplicationDbContext db, ILogger<DeviceAuthorizationController> logger)
    {
        _db = db; _logger = logger;
    }

    // POST /connect/device  (RFC 8628 Step 1)
    [HttpPost("device")]
    [AllowAnonymous]
    [EnableRateLimiting("rl.device")] // rate limit device authorization initiation
    public async Task<IActionResult> CreateDeviceAuthorization([FromForm] string client_id, [FromForm] string? scope = null)
    {
        if (string.IsNullOrWhiteSpace(client_id)) return BadRequest(new { error = "invalid_request", error_description = "client_id required" });
        var client = await _db.Clients.Include(c => c.Scopes).FirstOrDefaultAsync(c => c.ClientId == client_id && c.IsEnabled);
        if (client == null) return BadRequest(new { error = "invalid_client" });
        if (!client.AllowDeviceCodeFlow) return BadRequest(new { error = "unauthorized_client" });

        // Validate scopes against client assigned scopes
        var requestedScopes = (scope ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var allowedScopes = client.Scopes.Select(s => s.Scope).ToHashSet(StringComparer.Ordinal);
        var invalid = requestedScopes.Where(s => !allowedScopes.Contains(s)).ToList();
        if (invalid.Any())
        {
            return BadRequest(new { error = "invalid_scope", error_description = $"Invalid scopes: {string.Join(',', invalid)}" });
        }
        var normalizedScope = requestedScopes.Any() ? string.Join(' ', requestedScopes) : null;

        // Lifetime & polling interval
        var lifetimeMinutes = client.DeviceCodeLifetimeMinutes ?? 10;
        var pollInterval = client.DeviceCodePollingIntervalSeconds ?? 5;

        // Generate codes
        var deviceCode = GenerateOpaque(48);
        string userCode;
        do { userCode = GenerateUserCode(); } while (await _db.DeviceAuthorizations.AnyAsync(d => d.UserCode == userCode && d.Status == DeviceAuthorizationStatus.Pending));

        var record = new DeviceAuthorization
        {
            ClientId = client_id,
            DeviceCode = deviceCode,
            UserCode = userCode.ToUpperInvariant(),
            Scope = normalizedScope,
            ExpiresAt = DateTime.UtcNow.AddMinutes(lifetimeMinutes),
            PollingIntervalSeconds = pollInterval
        };
        _db.DeviceAuthorizations.Add(record);
        await _db.SaveChangesAsync();

        var verificationUri = Url.ActionLink(nameof(VerifyDeviceUserCode), values: new { user_code = userCode });
        var verificationUriComplete = verificationUri; // user_code already embedded via query param

        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        return Ok(new
        {
            device_code = deviceCode,
            user_code = userCode,
            verification_uri = verificationUri,
            verification_uri_complete = verificationUriComplete,
            expires_in = (int)TimeSpan.FromMinutes(lifetimeMinutes).TotalSeconds,
            interval = pollInterval
        });
    }

    // GET /connect/verify?user_code=XXXX-XXXX  (user enters code)
    [HttpGet("verify")]
    [AllowAnonymous]
    [EnableRateLimiting("rl.verify")] // rate limit verification lookups
    public async Task<IActionResult> VerifyDeviceUserCode([FromQuery] string? user_code)
    {
        // If not authenticated, defer until after login (but keep code)
        if (User.Identity?.IsAuthenticated != true)
        {
            var ret = Url.ActionLink(nameof(VerifyDeviceUserCode), values: new { user_code });
            return Redirect($"/connect/login?returnUrl={Uri.EscapeDataString(ret!)}");
        }

        DeviceAuthorization? rec = null;
        if (!string.IsNullOrWhiteSpace(user_code))
        {
            var norm = NormalizeUserCode(user_code);
            rec = await _db.DeviceAuthorizations.FirstOrDefaultAsync(d => d.UserCode == norm);
        }

        string? clientName = null;
        List<DeviceScopeInfo> scopeInfos = new();
        if (rec != null)
        {
            var client = await _db.Clients.Include(c => c.Scopes).FirstOrDefaultAsync(c => c.ClientId == rec.ClientId);
            clientName = client?.Name;
            if (!string.IsNullOrEmpty(rec.Scope))
            {
                var scopeNames = rec.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var dbScopes = await _db.Scopes.Where(s => scopeNames.Contains(s.Name)).ToListAsync();
                foreach (var s in scopeNames)
                {
                    var db = dbScopes.FirstOrDefault(x => x.Name == s);
                    scopeInfos.Add(new DeviceScopeInfo { Name = s, DisplayName = db?.DisplayName, Description = db?.Description });
                }
            }
        }

        var vm = new DeviceVerificationViewModel
        {
            InputUserCode = user_code,
            Found = rec != null,
            ClientId = rec?.ClientId,
            ClientName = clientName,
            Scope = rec?.Scope,
            ScopeDetails = scopeInfos,
            Status = rec?.Status,
            ExpiresAt = rec?.ExpiresAt,
            IsExpired = rec != null && rec.ExpiresAt <= DateTime.UtcNow
        };

        return View("Verify", vm);
    }

    // POST /connect/verify (approve/deny)
    [HttpPost("verify")]
    [ValidateAntiForgeryToken]
    [EnableRateLimiting("rl.verify")] // rate limit verification posts
    public async Task<IActionResult> PostVerify([FromForm] string user_code, [FromForm] string action)
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            var ret = Url.ActionLink(nameof(VerifyDeviceUserCode), values: new { user_code });
            return Redirect($"/connect/login?returnUrl={Uri.EscapeDataString(ret!)}");
        }

        var rec = await _db.DeviceAuthorizations.FirstOrDefaultAsync(d => d.UserCode == NormalizeUserCode(user_code));
        if (rec == null)
        {
            TempData["DeviceVerifyMessage"] = "Code not found";
            return RedirectToAction(nameof(VerifyDeviceUserCode), new { user_code });
        }
        if (rec.ExpiresAt <= DateTime.UtcNow)
        {
            rec.Status = DeviceAuthorizationStatus.Expired;
            await _db.SaveChangesAsync();
            TempData["DeviceVerifyMessage"] = "Code expired";
            return RedirectToAction(nameof(VerifyDeviceUserCode), new { user_code });
        }
        if (rec.Status is DeviceAuthorizationStatus.Approved or DeviceAuthorizationStatus.Denied or DeviceAuthorizationStatus.Consumed)
        {
            TempData["DeviceVerifyMessage"] = $"Request already {rec.Status}";
            return RedirectToAction(nameof(VerifyDeviceUserCode), new { user_code });
        }

        var sub = User.FindFirst(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject)?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(sub))
        {
            TempData["DeviceVerifyMessage"] = "User id missing in principal";
            return RedirectToAction(nameof(VerifyDeviceUserCode), new { user_code });
        }

        if (string.Equals(action, "approve", StringComparison.OrdinalIgnoreCase))
        {
            rec.Status = DeviceAuthorizationStatus.Approved;
            rec.Subject = sub;
            rec.ApprovedAt = DateTime.UtcNow;
            rec.VerificationIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            rec.VerificationUserAgent = Request.Headers.UserAgent.ToString();
            TempData["DeviceVerifyMessage"] = "Device authorization approved";
        }
        else
        {
            rec.Status = DeviceAuthorizationStatus.Denied;
            rec.DeniedAt = DateTime.UtcNow;
            TempData["DeviceVerifyMessage"] = "Device authorization denied";
        }
        await _db.SaveChangesAsync();
        return RedirectToAction(nameof(VerifyDeviceUserCode), new { user_code });
    }

    private static string GenerateOpaque(int bytes)
    {
        var b = System.Security.Cryptography.RandomNumberGenerator.GetBytes(bytes);
        return Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string GenerateUserCode()
    {
        // 8 char base32 groups like XXXX-XXXX
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/I/1
        Span<char> chars = stackalloc char[9];
        for (int i = 0; i < 4; i++) chars[i] = alphabet[Random.Shared.Next(alphabet.Length)];
        chars[4] = '-';
        for (int i = 5; i < 9; i++) chars[i] = alphabet[Random.Shared.Next(alphabet.Length)];
        return new string(chars);
    }

    private static string NormalizeUserCode(string code) => code.Trim().ToUpperInvariant();
}

public class DeviceVerificationViewModel
{
    public string? InputUserCode { get; set; }
    public bool Found { get; set; }
    public string? ClientId { get; set; }
    public string? ClientName { get; set; }
    public string? Scope { get; set; }
    public List<DeviceScopeInfo> ScopeDetails { get; set; } = new();
    public string? Status { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool IsExpired { get; set; }
}

public class DeviceScopeInfo
{
    public string Name { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
}
