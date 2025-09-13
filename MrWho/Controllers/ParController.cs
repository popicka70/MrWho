using System.Security.Cryptography;
using System.Text;
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
/// Minimal custom PAR (Pushed Authorization Request) endpoint implementation supporting optional JAR (request) objects.
/// Spec reference: RFC 9126. Endpoint: POST /connect/par
/// </summary>
[ApiController]
[Route("connect/par")]
[AllowAnonymous]
public class ParController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IJarRequestValidator _jarValidator;
    private readonly ILogger<ParController> _logger;

    public ParController(ApplicationDbContext db, IJarRequestValidator jarValidator, ILogger<ParController> logger)
    { _db = db; _jarValidator = jarValidator; _logger = logger; }

    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Post()
    {
        if (!Request.HasFormContentType)
            return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "form content type required" });
        var form = await Request.ReadFormAsync();
        var clientId = form[OpenIddictConstants.Parameters.ClientId].ToString();
        if (string.IsNullOrWhiteSpace(clientId))
            return BadRequest(new { error = OpenIddictConstants.Errors.InvalidClient, error_description = "client_id missing" });

        // Load client (basic enable check)
        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null || !client.IsEnabled)
            return BadRequest(new { error = OpenIddictConstants.Errors.InvalidClient, error_description = "unknown client" });

        // Collect standard parameters
        var responseType = form[OpenIddictConstants.Parameters.ResponseType].ToString();
        var redirectUri = form[OpenIddictConstants.Parameters.RedirectUri].ToString();
        var scope = form[OpenIddictConstants.Parameters.Scope].ToString();
        var state = form[OpenIddictConstants.Parameters.State].ToString();
        var codeChallenge = form[OpenIddictConstants.Parameters.CodeChallenge].ToString();
        var codeChallengeMethod = form[OpenIddictConstants.Parameters.CodeChallengeMethod].ToString();
        var requestJwt = form[OpenIddictConstants.Parameters.Request].ToString();

        Dictionary<string,string>? normalized = null;
        if (!string.IsNullOrWhiteSpace(requestJwt))
        {
            var result = await _jarValidator.ValidateAsync(requestJwt, clientId, HttpContext.RequestAborted);
            if (!result.Success)
            {
                return BadRequest(new { error = result.Error, error_description = result.ErrorDescription });
            }
            normalized = result.Parameters!; // recognized subset
            // Preserve state from form if not inside JWT
            if (!string.IsNullOrEmpty(state) && !normalized.ContainsKey(OpenIddictConstants.Parameters.State))
                normalized[OpenIddictConstants.Parameters.State] = state;
        }
        else
        {
            // Build normalized dictionary from raw form (minimal enforcement)
            normalized = new(StringComparer.OrdinalIgnoreCase)
            {
                [OpenIddictConstants.Parameters.ClientId] = clientId
            };
            if (!string.IsNullOrWhiteSpace(responseType)) normalized[OpenIddictConstants.Parameters.ResponseType] = responseType;
            if (!string.IsNullOrWhiteSpace(redirectUri)) normalized[OpenIddictConstants.Parameters.RedirectUri] = redirectUri;
            if (!string.IsNullOrWhiteSpace(scope)) normalized[OpenIddictConstants.Parameters.Scope] = scope;
            if (!string.IsNullOrWhiteSpace(state)) normalized[OpenIddictConstants.Parameters.State] = state;
            if (!string.IsNullOrWhiteSpace(codeChallenge))
            {
                normalized[OpenIddictConstants.Parameters.CodeChallenge] = codeChallenge;
                if (!string.IsNullOrWhiteSpace(codeChallengeMethod))
                    normalized[OpenIddictConstants.Parameters.CodeChallengeMethod] = codeChallengeMethod;
            }
        }

        // Future: enforce ParMode=Required logic here (client.ParMode) or additional validations
        // Lifetime: reuse existing configured lifetime (default 90s). Could adapt per client.
        var id = Guid.NewGuid().ToString("n");
        var requestUri = $"urn:ietf:params:oauth:request_uri:{id}";
        var expiresAt = DateTime.UtcNow.AddSeconds(90);

        // Serialize parameters (store raw JAR if present for optional later re-validation)
        var stored = new PushedAuthorizationRequest
        {
            Id = id,
            RequestUri = requestUri,
            ClientId = clientId,
            ParametersJson = JsonSerializer.Serialize(new
            {
                parameters = normalized,
                jar = string.IsNullOrWhiteSpace(requestJwt) ? null : requestJwt
            })
        };
        stored.ExpiresAt = expiresAt;
        _db.PushedAuthorizationRequests.Add(stored);
        await _db.SaveChangesAsync();

        return Ok(new { request_uri = requestUri, expires_in = 90 });
    }
}
