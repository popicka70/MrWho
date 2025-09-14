using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MrWho.Data;
using MrWho.Options;
using MrWho.Shared;

namespace MrWho.Services;

public interface IJarRequestValidator
{
    Task<JarValidationResult> ValidateAsync(string jwt, string? queryClientId, CancellationToken ct = default);
}

public sealed record JarValidationResult(bool Success, string? Error, string? ErrorDescription, string? ClientId, string? Algorithm, Dictionary<string, string>? Parameters);

internal sealed class JarRequestValidator : IJarRequestValidator
{
    private readonly ApplicationDbContext _db;
    private readonly IKeyManagementService _keys;
    private readonly IJarReplayCache _replay;
    private readonly ISymmetricSecretPolicy _symPolicy;
    private readonly IClientSecretService _secretService; // NEW: resolve plaintext via history
    private readonly JarOptions _options;
    private readonly ILogger<JarRequestValidator> _logger;

    private static readonly HashSet<string> _recognized = new(StringComparer.OrdinalIgnoreCase)
    {
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.ResponseType,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.RedirectUri,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.Scope,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.State,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.Nonce,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.CodeChallenge,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.CodeChallengeMethod
    };

    public JarRequestValidator(
        ApplicationDbContext db,
        IKeyManagementService keys,
        IJarReplayCache replay,
        ISymmetricSecretPolicy symPolicy,
        IClientSecretService secretService,
        IOptions<JarOptions> options,
        ILogger<JarRequestValidator> logger)
    {
        _db = db; _keys = keys; _replay = replay; _symPolicy = symPolicy; _secretService = secretService; _options = options.Value; _logger = logger;
    }

    public async Task<JarValidationResult> ValidateAsync(string jwt, string? queryClientId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(jwt)) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "empty request object", null, null, null);
        }

        if (jwt.Count(c => c == '.') != 2) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "request object must be JWT", null, null, null);
        }

        JwtSecurityToken token;
        var handler = new JwtSecurityTokenHandler();
        try { token = handler.ReadJwtToken(jwt); }
        catch (Exception ex)
        { _logger.LogDebug(ex, "JAR parse failed"); return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "invalid request object", null, null, null); }

        var alg = token.Header.Alg;
        if (string.IsNullOrWhiteSpace(alg)) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "missing alg", null, null, null);
        }

        var clientIdClaim = token.Payload.TryGetValue(OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId, out var cidObj) ? cidObj?.ToString() : null;
        if (!string.IsNullOrEmpty(queryClientId) && !string.IsNullOrEmpty(clientIdClaim) && !string.Equals(queryClientId, clientIdClaim, StringComparison.Ordinal)) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "client_id mismatch", null, alg, null);
        }

        var effectiveClientId = clientIdClaim ?? queryClientId;
        if (string.IsNullOrEmpty(effectiveClientId)) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "client_id missing", null, alg, null);
        }

        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == effectiveClientId, ct);
        if (client == null || !client.IsEnabled) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidClient, "unknown client", effectiveClientId, alg, null);
        }

        var expSeconds = token.Payload.Expiration; var now = DateTimeOffset.UtcNow;
        var exp = expSeconds.HasValue ? DateTimeOffset.FromUnixTimeSeconds(expSeconds.Value) : (DateTimeOffset?)null;
        if (exp is null || exp < now || exp > now.Add(_options.MaxExp)) {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "exp invalid", effectiveClientId, alg, null);
        }

        if (_options.RequireJti)
        {
            if (!token.Payload.TryGetValue("jti", out var jtiObj) || string.IsNullOrWhiteSpace(jtiObj?.ToString())) {
                return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "jti required", effectiveClientId, alg, null);
            }

            if (!_replay.TryAdd("jar:jti:" + jtiObj, exp.Value)) {
                return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "jti replay", effectiveClientId, alg, null);
            }
        }

        var tvp = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = true,
            ClockSkew = _options.ClockSkew,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            TryAllIssuerSigningKeys = true
        };

        bool isSymmetric = alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase);
        if (isSymmetric)
        {
            // Retrieve plaintext via secret history (client.ClientSecret is redaction placeholder)
            string? plainSecret = await _secretService.GetActivePlaintextAsync(effectiveClientId, ct);
            if (string.IsNullOrWhiteSpace(plainSecret))
            {
                _logger.LogDebug("HS* JAR validation failed: no active plaintext secret for client {ClientId}", effectiveClientId);
                return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "client secret missing", effectiveClientId, alg, null);
            }
            var res = _symPolicy.ValidateForAlgorithm(alg.ToUpperInvariant(), plainSecret);
            if (!res.Success)
            {
                _logger.LogDebug("HS* secret below policy for {ClientId} alg {Alg}: have {Have} need {Need}", effectiveClientId, alg, res.ActualBytes, res.RequiredBytes);
                return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "client secret length below policy", effectiveClientId, alg, null);
            }
            var keyBytes = Encoding.UTF8.GetBytes(plainSecret);
            tvp.IssuerSigningKey = new SymmetricSecurityKey(keyBytes) { KeyId = $"client:{effectiveClientId}:hs" };
        }
        else if (alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase))
        {
            // Prefer client-specific public key when provided; fallback to server signing keys (legacy behavior)
            if (!string.IsNullOrWhiteSpace(client.JarRsaPublicKeyPem))
            {
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportFromPem(client.JarRsaPublicKeyPem.AsSpan());
                    var pub = rsa.ExportParameters(false);
                    tvp.IssuerSigningKey = new RsaSecurityKey(pub) { KeyId = $"client:{effectiveClientId}:rs" };
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Invalid client JAR RSA public key for {ClientId}", effectiveClientId);
                    return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "invalid client JAR public key", effectiveClientId, alg, null);
                }
            }
            else
            {
                var (signing, _) = await _keys.GetActiveKeysAsync();
                tvp.IssuerSigningKeys = signing; // fallback
            }
        }
        else
        {
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "alg not supported", effectiveClientId, alg, null);
        }

        try
        {
            var jsonHandler = new JsonWebTokenHandler();
            var result = await jsonHandler.ValidateTokenAsync(jwt, tvp);
            if (!result.IsValid) {
                return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "signature invalid", effectiveClientId, alg, null);
            }
        }
        catch (Exception ex)
        { _logger.LogDebug(ex, "JAR signature validation failed"); return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, "signature invalid", effectiveClientId, alg, null); }

        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in _recognized)
        {
            if (token.Payload.TryGetValue(p, out var val) && val is not null) {
                dict[p] = val.ToString()!;
            }
        }
        dict[OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId] = effectiveClientId;
        return new(true, null, null, effectiveClientId, alg, dict);
    }
}
