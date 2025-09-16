using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using Microsoft.Extensions.Options;

namespace MrWho.Controllers;

[AllowAnonymous]
[ApiController]
public sealed class ParController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParController> _logger;
    private readonly IJarReplayCache _replay;
    private readonly JarOptions _jarOptions;
    private static readonly JsonWebTokenHandler JwtHandler = new();

    public ParController(ApplicationDbContext db, ILogger<ParController> logger, IJarReplayCache replay, IOptions<JarOptions> jarOptions)
    { _db = db; _logger = logger; _replay = replay; _jarOptions = jarOptions.Value; }

    [HttpPost]
    [Route("connect/par")] // explicit OIDC PAR endpoint
    public async Task<IActionResult> Post()
    {
        if (!Request.HasFormContentType)
        {
            return Error("invalid_request", "form_post_expected");
        }
        var form = await Request.ReadFormAsync();
        var clientId = form[OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId].ToString();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return Error("invalid_request", "client_id_missing");
        }

        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId);
        if (client == null || client.IsEnabled == false)
        {
            return Error("invalid_client", "unknown_client");
        }
        if (client.ParMode == MrWho.Shared.PushedAuthorizationMode.Disabled)
        {
            return Error("invalid_request", "PAR disabled for this client");
        }

        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in form)
        {
            if (kv.Key.Equals("client_secret", StringComparison.OrdinalIgnoreCase)) continue;
            dict[kv.Key] = kv.Value.ToString();
        }

        if (dict.TryGetValue(OpenIddict.Abstractions.OpenIddictConstants.Parameters.Request, out var requestJwt) && !string.IsNullOrWhiteSpace(requestJwt))
        {
            if (requestJwt.Length > _jarOptions.MaxRequestObjectBytes)
            {
                return Error("invalid_request_object", "request object too large");
            }
            try
            {
                var allowsRs = (client.AllowedRequestObjectAlgs ?? string.Empty)
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Any(a => a.StartsWith("RS", StringComparison.OrdinalIgnoreCase));
                SecurityKey? configuredRsaKey = null;
                if (allowsRs && !string.IsNullOrWhiteSpace(client.JarRsaPublicKeyPem))
                {
                    try
                    {
                        using var rsaProbe = RSA.Create();
                        rsaProbe.ImportFromPem(client.JarRsaPublicKeyPem.AsSpan());
                        var p = rsaProbe.ExportParameters(false);
                        if (p.Modulus == null || p.Modulus.Length * 8 < 2048)
                        {
                            return Error("invalid_request_object", "invalid RSA public key configured for client");
                        }
                        configuredRsaKey = new RsaSecurityKey(p);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[PAR] RSA public key import failed for client {ClientId}", clientId);
                        return Error("invalid_request_object", "invalid RSA public key configured for client");
                    }
                }

                // Additional heuristic: reject obviously short PEM bodies (<300 chars) for RS256 keys
                if (allowsRs && !string.IsNullOrWhiteSpace(client.JarRsaPublicKeyPem) && client.JarRsaPublicKeyPem.Length < 300)
                {
                    _logger.LogDebug("[PAR] RSA public key PEM too short for client {ClientId} length={Len}", clientId, client.JarRsaPublicKeyPem.Length);
                    return Error("invalid_request_object", "invalid RSA public key configured for client");
                }

                var jwt = JwtHandler.ReadJsonWebToken(requestJwt);
                var alg = jwt.Alg;
                if (client.RequireSignedRequestObject == true)
                {
                    if (string.IsNullOrEmpty(alg) || alg.Equals("none", StringComparison.OrdinalIgnoreCase))
                    {
                        return Error("invalid_request_object", "unsigned request object not allowed");
                    }
                    if (!string.IsNullOrWhiteSpace(client.AllowedRequestObjectAlgs))
                    {
                        var allowed = client.AllowedRequestObjectAlgs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        if (!allowed.Contains(alg, StringComparer.OrdinalIgnoreCase))
                        {
                            return Error("invalid_request_object", "algorithm not allowed");
                        }
                    }
                }

                // Strict signature validation against configured RSA key (if provided for RS* algs)
                if (configuredRsaKey != null)
                {
                    try
                    {
                        var tvp = new TokenValidationParameters
                        {
                            RequireSignedTokens = true,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false, // lifetime handled later in full JAR validator
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = configuredRsaKey,
                            SignatureValidator = null
                        };
                        // ValidateToken returns principal or throws; we only care that signature matches key
                        var result = JwtHandler.ValidateToken(requestJwt, tvp);
                        if (!result.IsValid)
                        {
                            return Error("invalid_request_object", "request object signature invalid");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[PAR] Signature validation failed for client {ClientId}", clientId);
                        return Error("invalid_request_object", "request object signature invalid");
                    }
                }

                var jti = jwt.Id;
                if (string.IsNullOrEmpty(jti))
                {
                    if (_jarOptions.RequireJti)
                    {
                        return Error("invalid_request_object", "missing jti");
                    }
                    jti = Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(requestJwt)));
                }
                long expEpoch = 0;
                if (jwt.TryGetPayloadValue<long>("exp", out var expVal)) expEpoch = expVal;
                var exp = expEpoch > 0 ? DateTimeOffset.FromUnixTimeSeconds(expEpoch) : DateTimeOffset.UtcNow.Add(_jarOptions.MaxExp);
                if (exp > DateTimeOffset.UtcNow + _jarOptions.MaxExp) exp = DateTimeOffset.UtcNow + _jarOptions.MaxExp;
                var cacheKey = "par_jti:" + clientId + ":" + jti;
                if (!_replay.TryAdd(cacheKey, exp))
                {
                    _logger.LogDebug("[PAR] JTI replay detected for client {ClientId} jti={Jti}", clientId, jti);
                    return Error("invalid_request", "replay jti");
                }
            }
            catch (Exception ex) when (ex is ArgumentException || ex is FormatException)
            {
                return Error("invalid_request_object", "malformed request object");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse request object for PAR submission");
                return Error("invalid_request_object", "malformed request object");
            }
        }

        var par = new PushedAuthorizationRequest
        {
            ClientId = clientId,
            ParametersJson = JsonSerializer.Serialize(dict),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddSeconds(90)
        };
        par.RequestUri = $"urn:ietf:params:oauth:request_uri:{par.Id}";
        _db.PushedAuthorizationRequests.Add(par);
        await _db.SaveChangesAsync();

        NoCache();
        return StatusCode(201, new { request_uri = par.RequestUri, expires_in = (int)(par.ExpiresAt - DateTime.UtcNow).TotalSeconds });
    }

    private IActionResult Error(string error, string description)
    {
        NoCache();
        return BadRequest(new { error, error_description = description });
    }

    private void NoCache()
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Pragma"] = "no-cache";
    }
}
