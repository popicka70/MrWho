using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens; // added for Base64UrlEncoder
using MrWho.Data;
using MrWho.Models;
using MrWho.Services; // for IJarReplayCache, JarOptions
using Microsoft.Extensions.Options;

namespace MrWho.Controllers;

/// <summary>
/// Pushed Authorization Request (PAR) endpoint implementation (RFC 9126).
/// POST /connect/par with standard authorization request parameters.
/// Stores the parameters server-side and returns a request_uri reference.
/// </summary>
[AllowAnonymous]
[Route("connect")]
public sealed class ParController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParController> _logger;
    private readonly IJarReplayCache _replay;
    private readonly JarOptions _jarOptions;

    private static readonly JsonWebTokenHandler JwtHandler = new();

    public ParController(ApplicationDbContext db, ILogger<ParController> logger, IJarReplayCache replay, IOptions<JarOptions> jarOptions)
    { _db = db; _logger = logger; _replay = replay; _jarOptions = jarOptions.Value; }

    [HttpPost("par")]
    public async Task<IActionResult> Post()
    {
        if (!Request.HasFormContentType)
        {
            return BadRequest(new { error = "invalid_request", error_description = "form_post_expected" });
        }
        var form = await Request.ReadFormAsync();
        var clientId = form[OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId].ToString();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return BadRequest(new { error = "invalid_request", error_description = "client_id_missing" });
        }

        // Validate client exists and enabled
        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null || client.IsEnabled == false)
        {
            return BadRequest(new { error = "invalid_client", error_description = "unknown_client" });
        }
        // If PAR disabled for this client
        if (client.ParMode == Shared.PushedAuthorizationMode.Disabled)
        {
            return BadRequest(new { error = "invalid_request", error_description = "PAR disabled for this client" });
        }

        // Build dictionary of parameters (string values only for now)
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in form)
        {
            if (kv.Key.Equals("client_secret", StringComparison.OrdinalIgnoreCase)) continue; // don't persist secret
            dict[kv.Key] = kv.Value.ToString();
        }

        // Optional JAR replay/jti checks (basic – signature validation happens later in pipeline)
        if (dict.TryGetValue(OpenIddict.Abstractions.OpenIddictConstants.Parameters.Request, out var requestJwt) && !string.IsNullOrWhiteSpace(requestJwt))
        {
            if (requestJwt.Length > _jarOptions.MaxRequestObjectBytes)
            {
                return BadRequest(new { error = "invalid_request_object", error_description = "request object too large" });
            }
            try
            {
                var jwt = JwtHandler.ReadJsonWebToken(requestJwt);
                var jti = jwt.Id;
                if (string.IsNullOrEmpty(jti))
                {
                    if (_jarOptions.RequireJti)
                    {
                        return BadRequest(new { error = "invalid_request_object", error_description = "missing jti" });
                    }
                    jti = Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(requestJwt)));
                }
                long expEpoch = 0;
                if (jwt.TryGetPayloadValue<long>("exp", out var expVal))
                {
                    expEpoch = expVal;
                }
                var exp = expEpoch > 0 ? DateTimeOffset.FromUnixTimeSeconds(expEpoch) : DateTimeOffset.UtcNow.Add(_jarOptions.MaxExp);
                if (exp > DateTimeOffset.UtcNow + _jarOptions.MaxExp)
                {
                    exp = DateTimeOffset.UtcNow + _jarOptions.MaxExp;
                }
                var cacheKey = "par_jti:" + clientId + ":" + jti;
                if (!_replay.TryAdd(cacheKey, exp))
                {
                    // Align with JAR validator behaviour
                    return BadRequest(new { error = "invalid_request_object", error_description = "jti replay" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse request object for PAR submission");
                return BadRequest(new { error = "invalid_request_object", error_description = "malformed request object" });
            }
        }

        // Persist
        var par = new PushedAuthorizationRequest
        {
            ClientId = clientId,
            ParametersJson = JsonSerializer.Serialize(dict),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddSeconds(90) // default short lifetime
        };
        par.RequestUri = $"urn:ietf:params:oauth:request_uri:{par.Id}";
        _db.PushedAuthorizationRequests.Add(par);
        await _db.SaveChangesAsync();

        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Pragma"] = "no-cache";
        return StatusCode(201, new { request_uri = par.RequestUri, expires_in = (int)(par.ExpiresAt - DateTime.UtcNow).TotalSeconds });
    }
}
