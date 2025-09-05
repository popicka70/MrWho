using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace MrWho.Controllers;

[ApiController]
[Route("connect")] // align with OIDC base path
public class DeviceAuthorizationController : ControllerBase
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
    public async Task<IActionResult> CreateDeviceAuthorization([FromForm] string client_id, [FromForm] string? scope = null)
    {
        if (string.IsNullOrWhiteSpace(client_id)) return BadRequest(new { error = "invalid_request", error_description = "client_id required" });
        var client = await _db.Clients.FirstOrDefaultAsync(c => c.ClientId == client_id && c.IsEnabled);
        if (client == null) return BadRequest(new { error = "invalid_client" });
        if (!client.AllowDeviceCodeFlow) return BadRequest(new { error = "unauthorized_client" });

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
            UserCode = userCode,
            Scope = scope,
            ExpiresAt = DateTime.UtcNow.AddMinutes(lifetimeMinutes),
            PollingIntervalSeconds = pollInterval
        };
        _db.DeviceAuthorizations.Add(record);
        await _db.SaveChangesAsync();

        var verificationUri = Url.ActionLink(nameof(VerifyDeviceUserCode), values: new { user_code = userCode });
        var verificationUriComplete = verificationUri; // user_code already embedded via query param

        return Ok(new {
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
    public async Task<IActionResult> VerifyDeviceUserCode([FromQuery] string? user_code)
    {
        if (string.IsNullOrWhiteSpace(user_code)) return Content("Missing user_code");
        var rec = await _db.DeviceAuthorizations.FirstOrDefaultAsync(d => d.UserCode == NormalizeUserCode(user_code));
        if (rec == null || rec.ExpiresAt <= DateTime.UtcNow)
        {
            return Content("Code invalid or expired");
        }
        if (User.Identity?.IsAuthenticated != true)
        {
            // redirect to login preserving return path
            var returnUrl = Url.ActionLink(nameof(VerifyDeviceUserCode), values: new { user_code });
            return Redirect($"/connect/login?returnUrl={Uri.EscapeDataString(returnUrl!)}");
        }

        // Show simple approval page
        return Content($"Device authorization request for client '{rec.ClientId}' with scopes: {rec.Scope ?? "(none)"}. POST approval to /connect/verify with form fields user_code + action=approve or deny.");
    }

    // POST /connect/verify (approve/deny)
    [HttpPost("verify")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> PostVerify([FromForm] string user_code, [FromForm] string action)
    {
        var rec = await _db.DeviceAuthorizations.FirstOrDefaultAsync(d => d.UserCode == NormalizeUserCode(user_code));
        if (rec == null) return Content("Invalid code");
        if (rec.ExpiresAt <= DateTime.UtcNow)
        {
            rec.Status = DeviceAuthorizationStatus.Expired;
            await _db.SaveChangesAsync();
            return Content("Code expired");
        }
        if (rec.Status is DeviceAuthorizationStatus.Approved or DeviceAuthorizationStatus.Denied or DeviceAuthorizationStatus.Consumed)
        {
            return Content($"Already {rec.Status}");
        }
        if (User.Identity?.IsAuthenticated != true)
        {
            var ret = Url.ActionLink(nameof(VerifyDeviceUserCode), values: new { user_code });
            return Redirect($"/connect/login?returnUrl={Uri.EscapeDataString(ret!)}");
        }
        var sub = User.FindFirst(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject)?.Value ?? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(sub)) return Content("User id missing in principal");

        if (string.Equals(action, "approve", StringComparison.OrdinalIgnoreCase))
        {
            rec.Status = DeviceAuthorizationStatus.Approved;
            rec.Subject = sub;
            rec.ApprovedAt = DateTime.UtcNow;
            rec.VerificationIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            rec.VerificationUserAgent = Request.Headers.UserAgent.ToString();
        }
        else
        {
            rec.Status = DeviceAuthorizationStatus.Denied;
            rec.DeniedAt = DateTime.UtcNow;
        }
        await _db.SaveChangesAsync();
        return Content($"Device authorization {rec.Status}.");
    }

    private static string GenerateOpaque(int bytes)
    {
        var b = System.Security.Cryptography.RandomNumberGenerator.GetBytes(bytes);
        return Convert.ToBase64String(b).Replace('+','-').Replace('/','_').TrimEnd('=');
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
