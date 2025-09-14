using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;

namespace MrWho.Controllers;

/// <summary>
/// Implements a protected dynamic client registration endpoint.
/// Phase 1: requests are captured and queued for admin approval (no unauthenticated self-service yet).
/// RFC 7591 subset.
/// </summary>
[Route("connect/register")]
[ApiController]
[Authorize] // admin portal users only initial slice
public class DynamicClientRegistrationController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IOidcClientService _clientSync;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly ILogger<DynamicClientRegistrationController> _logger;

    public DynamicClientRegistrationController(ApplicationDbContext db, IOidcClientService clientSync, IOpenIddictScopeManager scopeManager, ILogger<DynamicClientRegistrationController> logger)
    {
        _db = db; _clientSync = clientSync; _scopeManager = scopeManager; _logger = logger;
    }

    [HttpPost]
    [Consumes("application/json")]
    [Produces("application/json")]
    public async Task<IActionResult> Register([FromBody] DynamicClientRegistrationRequest request, CancellationToken ct)
    {
        if (request == null) {
            return BadRequest(new { error = "invalid_request", error_description = "Missing body" });
        }

        var (ok, error) = DynamicClientRegistrationValidation.Validate(request);
        if (!ok) {
            return BadRequest(new { error = "invalid_client_metadata", error_description = error });
        }

        // Queue into admin approval table
        var userId = User.FindFirstValue(OpenIddictConstants.Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        var userName = User.Identity?.Name ?? userId;
        var pending = PendingClientRegistration.FromRequest(request, userId, userName);

        _db.PendingClientRegistrations.Add(pending);
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("Queued dynamic client registration {RegistrationId} by {User}", pending.Id, userName);

        // Return 202 Accepted with registration record id
        return Accepted(new
        {
            registration_id = pending.Id,
            status = pending.Status.ToString().ToLowerInvariant(),
            message = "Registration submitted for approval"
        });
    }
}
