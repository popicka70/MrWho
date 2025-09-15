using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
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

// New higher-level service (alias) used by OpenIddict handlers going forward.
public interface IJarValidationService
{
    Task<JarValidationResult> ValidateAsync(string jwt, string? queryClientId, CancellationToken ct = default);
}

public sealed record JarValidationResult(bool Success, string? Error, string? ErrorDescription, string? ClientId, string? Algorithm, Dictionary<string, string>? Parameters);

internal sealed class JarRequestValidator : IJarRequestValidator, IJarValidationService
{
    private readonly ApplicationDbContext _db;
    private readonly IKeyManagementService _keys;
    private readonly IJarReplayCache _replay;
    private readonly ISymmetricSecretPolicy _symPolicy;
    private readonly IClientSecretService _secretService;
    private readonly JarOptions _options;
    private readonly ILogger<JarRequestValidator> _logger;
    private readonly string? _serverIssuer; // expected audience value

    private static readonly HashSet<string> _recognized = new(StringComparer.OrdinalIgnoreCase)
    {
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.ResponseType,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.RedirectUri,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.Scope,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.State,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.Nonce,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.CodeChallenge,
        OpenIddict.Abstractions.OpenIddictConstants.Parameters.CodeChallengeMethod,
        "jti"
    };

    public JarRequestValidator(
        ApplicationDbContext db,
        IKeyManagementService keys,
        IJarReplayCache replay,
        ISymmetricSecretPolicy symPolicy,
        IClientSecretService secretService,
        IOptions<JarOptions> options,
        ILogger<JarRequestValidator> logger,
        IConfiguration configuration)
    { _db = db; _keys = keys; _replay = replay; _symPolicy = symPolicy; _secretService = secretService; _options = options.Value; _logger = logger; _serverIssuer = (configuration["OpenIddict:Issuer"] ?? configuration["Authentication:Authority"])?.TrimEnd('/'); }

    public Task<JarValidationResult> ValidateAsync(string jwt, string? queryClientId, CancellationToken ct = default)
        => ValidateCoreAsync(jwt, queryClientId, ct);
    Task<JarValidationResult> IJarRequestValidator.ValidateAsync(string jwt, string? queryClientId, CancellationToken ct) => ValidateCoreAsync(jwt, queryClientId, ct);

    private async Task<JarValidationResult> ValidateCoreAsync(string jwt, string? queryClientId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return Fail(null, null, "empty request object");

        if (_options.MaxRequestObjectBytes > 0 && Encoding.UTF8.GetByteCount(jwt) > _options.MaxRequestObjectBytes)
            return Fail(null, null, "request object too large");

        if (jwt.Count(c => c == '.') != 2)
            return Fail(null, null, "request object must be JWT");

        JwtSecurityToken token;
        try { token = new JwtSecurityTokenHandler().ReadJwtToken(jwt); }
        catch (Exception ex) { _logger.LogDebug(ex, "JAR parse failed"); return Fail(null, null, "invalid request object"); }

        var alg = token.Header.Alg;
        if (string.IsNullOrWhiteSpace(alg))
            return Fail(null, null, "missing alg");

        var clientIdClaim = token.Payload.TryGetValue(OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId, out var cidObj) ? cidObj?.ToString() : null;
        if (!string.IsNullOrEmpty(queryClientId) && !string.IsNullOrEmpty(clientIdClaim) && !string.Equals(queryClientId, clientIdClaim, StringComparison.Ordinal))
            return Fail(null, alg, "client_id mismatch");

        var effectiveClientId = clientIdClaim ?? queryClientId;
        if (string.IsNullOrEmpty(effectiveClientId))
            return Fail(null, alg, "client_id missing");

        var client = await _db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == effectiveClientId, ct);
        if (client == null || !client.IsEnabled)
            return new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidClient, "unknown client", effectiveClientId, alg, null);

        // Allowed algorithms enforcement (per-client)
        if (!string.IsNullOrWhiteSpace(client.AllowedRequestObjectAlgs))
        {
            var allowed = client.AllowedRequestObjectAlgs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(a => a.ToUpperInvariant()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!allowed.Contains(alg))
                return Fail(effectiveClientId, alg, "alg not allowed");
        }
        else
        {
            // Default allow only RS256 + HS256 unless explicitly broadened
            if (!alg.Equals("RS256", StringComparison.OrdinalIgnoreCase) && !alg.Equals("HS256", StringComparison.OrdinalIgnoreCase) && !alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase) && !alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
                return Fail(effectiveClientId, alg, "alg not supported");
        }

        var now = DateTimeOffset.UtcNow;
        var expSeconds = token.Payload.Expiration;
        var exp = expSeconds.HasValue ? DateTimeOffset.FromUnixTimeSeconds(expSeconds.Value) : (DateTimeOffset?)null;
        if (exp is null || exp < now || exp > now.Add(_options.MaxExp))
            return Fail(effectiveClientId, alg, "exp invalid");

        // iat (IssuedAt) sanity: not in future beyond skew and not older than max window
        var issuedAt = token.IssuedAt; // DateTime (Kind=Utc)
        if (issuedAt != DateTime.MinValue)
        {
            var iat = new DateTimeOffset(issuedAt.ToUniversalTime());
            if (iat > now.Add(_options.ClockSkew) || iat < now.Add(-_options.MaxExp))
                return Fail(effectiveClientId, alg, "iat invalid");
        }
        // nbf (NotBefore) sanity
        var notBefore = token.ValidFrom; // NBF maps to ValidFrom
        if (notBefore != DateTime.MinValue)
        {
            var nbf = new DateTimeOffset(notBefore.ToUniversalTime());
            if (nbf > now.Add(_options.ClockSkew))
                return Fail(effectiveClientId, alg, "nbf in future");
        }

        if (_options.RequireJti)
        {
            if (!token.Payload.TryGetValue("jti", out var jtiObj) || string.IsNullOrWhiteSpace(jtiObj?.ToString()))
                return Fail(effectiveClientId, alg, "jti required");
            if (!_replay.TryAdd("jar:jti:" + jtiObj, exp.Value))
                return Fail(effectiveClientId, alg, "jti replay");
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
            var plainSecret = await _secretService.GetActivePlaintextAsync(effectiveClientId, ct);
            if (string.IsNullOrWhiteSpace(plainSecret))
                return Fail(effectiveClientId, alg, "client secret missing");
            var res = _symPolicy.ValidateForAlgorithm(alg.ToUpperInvariant(), plainSecret);
            if (!res.Success)
                return Fail(effectiveClientId, alg, "client secret length below policy");
            tvp.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(plainSecret)) { KeyId = $"client:{effectiveClientId}:hs" };
        }
        else if (alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(client.JarRsaPublicKeyPem))
            {
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportFromPem(client.JarRsaPublicKeyPem.AsSpan());
                    tvp.IssuerSigningKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = $"client:{effectiveClientId}:rs" };
                }
                catch (Exception ex)
                { _logger.LogDebug(ex, "Invalid client JAR RSA public key for {ClientId}", effectiveClientId); return Fail(effectiveClientId, alg, "invalid client JAR public key"); }
            }
            else
            {
                var (signing, _) = await _keys.GetActiveKeysAsync();
                tvp.IssuerSigningKeys = signing; // fallback
            }
        }
        else
            return Fail(effectiveClientId, alg, "alg not supported");

        try
        {
            var jsonHandler = new JsonWebTokenHandler();
            var result = await jsonHandler.ValidateTokenAsync(jwt, tvp);
            if (!result.IsValid)
                return Fail(effectiveClientId, alg, "signature invalid");
        }
        catch (Exception ex)
        { _logger.LogDebug(ex, "JAR signature validation failed"); return Fail(effectiveClientId, alg, "signature invalid"); }

        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in _recognized)
            if (token.Payload.TryGetValue(p, out var val) && val is not null)
                dict[p] = val.ToString()!;
        dict[OpenIddict.Abstractions.OpenIddictConstants.Parameters.ClientId] = effectiveClientId;
        return new(true, null, null, effectiveClientId, alg, dict);
    }

    private JarValidationResult Fail(string? clientId, string? alg, string description)
        => new(false, OpenIddict.Abstractions.OpenIddictConstants.Errors.InvalidRequestObject, description, clientId, alg, null);
}
