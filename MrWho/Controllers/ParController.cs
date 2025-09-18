using System.Text.Json;
using System.Security.Cryptography; // added
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using OpenIddict.Abstractions;

namespace MrWho.Controllers;

[Route("connect")]
public class ParController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParController> _logger;
    private readonly IJarReplayCache _replay; // now required
    private readonly IProtocolMetrics _metrics;
    private readonly IJarValidationService _jarValidator;

    public ParController(ApplicationDbContext db, ILogger<ParController> logger, IProtocolMetrics metrics, IJarValidationService jarValidator, IJarReplayCache replay)
    { _db = db; _logger = logger; _metrics = metrics; _jarValidator = jarValidator; _replay = replay; }

    [HttpPost("par")]
    [AllowAnonymous]
    public async Task<IActionResult> Push()
    {
        if (Request.Headers.ContainsKey("Authorization"))
        {
            try { Request.Headers.Remove("Authorization"); } catch { }
        }

        try
        {
            if (!Request.HasFormContentType)
            {
                _metrics.IncrementParPush("error");
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "Form content required" });
            }

            var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
            var clientId = form[OpenIddictConstants.Parameters.ClientId].ToString();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                _metrics.IncrementParPush("error");
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidClient });
            }

            var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsEnabled, HttpContext.RequestAborted);
            if (client is null)
            {
                _metrics.IncrementParPush("error");
                return BadRequest(new { error = OpenIddictConstants.Errors.InvalidClient });
            }

            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in form)
            {
                var key = kv.Key;
                var val = kv.Value.ToString();
                if (string.Equals(key, OpenIddictConstants.Parameters.ClientSecret, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (string.Equals(key, OpenIddictConstants.Parameters.RequestUri, StringComparison.OrdinalIgnoreCase))
                    continue;
                dict[key] = val;
            }

            string? requestJwt = null;
            if (dict.TryGetValue(OpenIddictConstants.Parameters.Request, out var rawRequest) && !string.IsNullOrWhiteSpace(rawRequest))
            {
                requestJwt = rawRequest;

                // Secondary replay guard based on raw JAR content hash
                try
                {
                    using var sha = SHA256.Create();
                    var hash = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(requestJwt));
                    var hashB64 = Convert.ToBase64String(hash);
                    var hashKey = $"par_jwt_hash:{clientId}:{hashB64}";
                    if (!_replay.TryAdd(hashKey, DateTimeOffset.UtcNow.AddMinutes(5)))
                    {
                        _metrics.IncrementParPush("reused");
                        return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "replay jwt" });
                    }
                }
                catch { }

                // DB-level duplicate detection (same client, same request JWT, unexpired)
                try
                {
                    var nowUtc = DateTime.UtcNow;
                    var candidates = await _db.PushedAuthorizationRequests.AsNoTracking()
                        .Where(p => p.ClientId == clientId && p.ExpiresAt > nowUtc)
                        .OrderByDescending(p => p.CreatedAt)
                        .Take(20) // small window
                        .ToListAsync(HttpContext.RequestAborted);
                    foreach (var cand in candidates)
                    {
                        try
                        {
                            if (string.IsNullOrWhiteSpace(cand.ParametersJson)) continue;
                            var cdict = JsonSerializer.Deserialize<Dictionary<string, string>>(cand.ParametersJson);
                            if (cdict != null && cdict.TryGetValue(OpenIddictConstants.Parameters.Request, out var prev) && !string.IsNullOrEmpty(prev))
                            {
                                if (string.Equals(prev, requestJwt, StringComparison.Ordinal))
                                {
                                    _metrics.IncrementParPush("reused");
                                    return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "replay jwt" });
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                try
                {
                    var result = await _jarValidator.ValidateAsync(requestJwt, clientId, HttpContext.RequestAborted);
                    if (!result.Success)
                    {
                        _logger.LogDebug("[PAR] Rejecting invalid request object at push (alg={Alg}, error={Error}, desc={Desc})", result.Algorithm, result.Error, result.ErrorDescription);
                        _metrics.IncrementParPush("invalid");
                        return BadRequest(new { error = result.Error ?? OpenIddictConstants.Errors.InvalidRequest, error_description = result.ErrorDescription ?? "invalid request object" });
                    }

                    // Enforce PAR jti replay after successful validation
                    string? jti = null;
                    if (result.Parameters != null && result.Parameters.TryGetValue("jti", out var jtiVal)) jti = jtiVal;
                    if (string.IsNullOrWhiteSpace(jti))
                    {
                        try { var jwt = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(requestJwt); jti = jwt.Id; } catch { }
                    }
                    if (!string.IsNullOrWhiteSpace(jti))
                    {
                        var exp = DateTimeOffset.UtcNow.AddMinutes(5);
                        if (result.Parameters != null && result.Parameters.TryGetValue("exp", out var expStr) && long.TryParse(expStr, out var expEpoch))
                        { try { exp = DateTimeOffset.FromUnixTimeSeconds(expEpoch); } catch { } }

                        if (!_replay.TryAdd($"par_jti:{clientId}:{jti}", exp))
                        {
                            _metrics.IncrementParPush("reused");
                            return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequest, error_description = "replay jti" });
                        }
                        _logger.LogDebug("[PAR] Stored jti for replay detection key=par_jti:{ClientId}:{Jti} exp={Exp}", clientId, jti, exp);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PAR] Validation threw for request object; rejecting");
                    _metrics.IncrementParPush("invalid");
                    return BadRequest(new { error = OpenIddictConstants.Errors.InvalidRequestObject, error_description = "invalid request object" });
                }
            }

            var id = Guid.NewGuid().ToString("n");
            var requestUri = $"urn:ietf:params:oauth:request_uri:{id}";
            var expiresIn = 90; // seconds
            var entity = new PushedAuthorizationRequest
            {
                Id = id,
                RequestUri = requestUri,
                ClientId = clientId,
                ParametersJson = JsonSerializer.Serialize(dict),
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn)
            };
            _db.PushedAuthorizationRequests.Add(entity);
            await _db.SaveChangesAsync(HttpContext.RequestAborted);

            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";
            _metrics.IncrementParPush("created");
            return Ok(new { request_uri = requestUri, expires_in = expiresIn });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PAR push failed");
            _metrics.IncrementParPush("error");
            return StatusCode(500, new { error = OpenIddictConstants.Errors.ServerError, error_description = ex.Message });
        }
    }
}
