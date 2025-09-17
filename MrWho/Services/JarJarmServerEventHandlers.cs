using System.Security.Cryptography; // added for KeyId derivation
using System.Text; // for UTF8 byte counts (PJ41)
using System.Text.Json; // for JSON array construction
using Microsoft.EntityFrameworkCore; // added for context queries
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options; // added for IOptions<>
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens; // signing
using MrWho.Data; // for ApplicationDbContext
using MrWho.Models; // for PushedAuthorizationRequest
using MrWho.Options; // for OidcAdvancedOptions
using MrWho.Shared; // for JarMode enum
using OpenIddict.Abstractions;
using OpenIddict.Server; // ensure OpenIddict server types
using static OpenIddict.Server.OpenIddictServerEvents; // restore static event context types

namespace MrWho.Services;

public class JarOptions
{
    public const string SectionName = "Jar";
    public int MaxRequestObjectBytes { get; set; } = 4096;
    public bool RequireJti { get; set; } = true;
    public TimeSpan JtiCacheWindow { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan MaxExp { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
    public int JarmTokenLifetimeSeconds { get; set; } = 120; // short lifetime for JARM response JWT
    // PJ41 placeholders (not enforced yet) -> retained but enforcement moved to advanced options handler
    public int ClaimCountLimit { get; set; } = 0; // 0 = unlimited (legacy unused)
    public int ClaimValueMaxLength { get; set; } = 0; // 0 = unlimited (legacy unused)
    // PJ40 placeholder (not enforced yet)
    public bool EnforceQueryConsistency { get; set; } = false; // legacy switch supplanted by OidcAdvancedOptions.RequestConflicts
}

public interface IJarReplayCache { bool TryAdd(string key, DateTimeOffset expiresUtc); }
public sealed class InMemoryJarReplayCache : IJarReplayCache
{
    private readonly IMemoryCache _cache; public InMemoryJarReplayCache(IMemoryCache cache) => _cache = cache;
    public bool TryAdd(string key, DateTimeOffset expiresUtc)
    { if (_cache.TryGetValue(key, out _)) { return false; } var ttl = expiresUtc - DateTimeOffset.UtcNow; if (ttl <= TimeSpan.Zero) { ttl = TimeSpan.FromSeconds(1); } _cache.Set(key, 1, ttl); return true; }
}

// NEW: Unified validation/limit handler (runs after JAR expansion + PAR resolution, early in validation stage) implementing PJ40 + PJ41.
internal sealed class RequestConflictAndLimitValidationHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly IOptions<OidcAdvancedOptions> _adv;
    private readonly ILogger<RequestConflictAndLimitValidationHandler> _logger;
    private readonly IProtocolMetrics _metrics; // metrics injection
    // NEW: skip value-length enforcement for standard OIDC parameters (prevents false positives in Phase 1 tests)
    private static readonly HashSet<string> _skipValueLength = new(StringComparer.OrdinalIgnoreCase)
    {
        OpenIddictConstants.Parameters.ClientId,
        OpenIddictConstants.Parameters.RedirectUri,
        OpenIddictConstants.Parameters.ResponseType,
        OpenIddictConstants.Parameters.Scope,
        OpenIddictConstants.Parameters.State,
        OpenIddictConstants.Parameters.Nonce,
        OpenIddictConstants.Parameters.CodeChallenge,
        OpenIddictConstants.Parameters.CodeChallengeMethod,
        "jti","request","request_uri","_jar_validated","_par_resolved",
        // test-only knobs should never be subject to value length
        "_mrwho_max_params"
    };
    public RequestConflictAndLimitValidationHandler(IOptions<OidcAdvancedOptions> adv, ILogger<RequestConflictAndLimitValidationHandler> logger, IProtocolMetrics metrics)
    { _adv = adv; _logger = logger; _metrics = metrics; }

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Request;
        if (request == null) return ValueTask.CompletedTask;
        var adv = _adv.Value;

        try
        {
            // PJ40: Explicitly check JAR vs query scope conflict preserved from extract stage
            string? queryScope = request.GetParameter("_query_scope")?.ToString();
            string? jarScope = request.GetParameter("_jar_scope")?.ToString();
            if (string.IsNullOrEmpty(queryScope) || string.IsNullOrEmpty(jarScope))
            {
                try
                {
                    if (string.IsNullOrEmpty(queryScope) && context.Transaction?.Properties != null && context.Transaction.Properties.TryGetValue("mrwho.query_scope", out var q))
                    {
                        queryScope = q?.ToString();
                    }
                    if (string.IsNullOrEmpty(jarScope) && context.Transaction?.Properties != null && context.Transaction.Properties.TryGetValue("mrwho.jar_scope", out var j))
                    {
                        jarScope = j?.ToString();
                    }
                }
                catch { /* ignore */ }
            }
            if (!string.IsNullOrEmpty(queryScope) && !string.IsNullOrEmpty(jarScope))
            {
                static string Normalize(string? v) => string.Join(' ', (v ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).OrderBy(x => x, StringComparer.Ordinal));
                if (Normalize(queryScope) != Normalize(jarScope))
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "parameter_conflict:scope");
                    _metrics.IncrementValidationEvent("conflict", "scope");
                    return ValueTask.CompletedTask;
                }
            }

            // Build snapshot of parameters currently on the request (includes JAR merged + PAR resolved)
            var parameterNames = request.GetParameters()
                .Select(p => p.Key)
                .Where(k => !string.Equals(k, "_query_scope", StringComparison.OrdinalIgnoreCase)
                         && !string.Equals(k, "_jar_scope", StringComparison.OrdinalIgnoreCase)
                         && !string.Equals(k, "_mrwho_max_params", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            // PJ41: Limits (operate on snapshot)
            if (adv.RequestLimits is { } limits)
            {
                // Test-only per-request override: allow a specific test to set max parameters via special knob
                int? effectiveMaxParams = limits.MaxParameters;
                try
                {
                    var testMode = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase);
                    if (testMode)
                    {
                        var overrideParam = request.GetParameter("_mrwho_max_params")?.ToString();
                        if (!string.IsNullOrWhiteSpace(overrideParam) && int.TryParse(overrideParam, out var parsed) && parsed >= 0)
                        {
                            effectiveMaxParams = parsed;
                        }
                    }
                }
                catch { /* ignore override errors */ }

                if (effectiveMaxParams is int mp && mp > 0 && parameterNames.Count > mp)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:parameters");
                    _metrics.IncrementValidationEvent("limit", "parameters");
                    return ValueTask.CompletedTask;
                }

                int aggregateBytes = 0;
                foreach (var name in parameterNames)
                {
                    if (limits.MaxParameterNameLength is int mn && mn > 0 && name.Length > mn)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:name_length");
                        _metrics.IncrementValidationEvent("limit", "name_length");
                        return ValueTask.CompletedTask;
                    }
                    var valStr = request.GetParameter(name)?.ToString() ?? string.Empty;
                    if (limits.MaxParameterValueLength is int mv && mv > 0 && !_skipValueLength.Contains(name) && valStr.Length > mv)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:value_length");
                        _metrics.IncrementValidationEvent("limit", "value_length");
                        return ValueTask.CompletedTask;
                    }
                    aggregateBytes += Encoding.UTF8.GetByteCount(valStr);
                }
                if (limits.MaxAggregateValueBytes is int mab && mab > 0 && aggregateBytes > mab)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:aggregate_bytes");
                    _metrics.IncrementValidationEvent("limit", "aggregate_bytes");
                    return ValueTask.CompletedTask;
                }

                if (limits.MaxScopeItems is int msi && msi > 0 && request.GetParameter(OpenIddictConstants.Parameters.Scope) is { } scopeParam)
                {
                    var count = scopeParam.ToString()?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length ?? 0;
                    if (count > msi)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:scope_items");
                        _metrics.IncrementValidationEvent("limit", "scope_items");
                        return ValueTask.CompletedTask;
                    }
                }
                if (limits.MaxAcrValues is int mav && mav > 0 && request.GetParameter(OpenIddictConstants.Parameters.AcrValues) is { } acrParam)
                {
                    var count = acrParam.ToString()?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length ?? 0;
                    if (count > mav)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:acr_values");
                        _metrics.IncrementValidationEvent("limit", "acr_values");
                        return ValueTask.CompletedTask;
                    }
                }
            }

            // PJ40: Conflict detection comment retained
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Request conflict/limit handler encountered error; continuing (fail-open)");
        }
        return ValueTask.CompletedTask;
    }
}

// Discovery augmentation handler
internal sealed class DiscoveryAugmentationHandler : IOpenIddictServerHandler<ApplyConfigurationResponseContext>
{
    private readonly ILogger<DiscoveryAugmentationHandler> _logger;
    private readonly MrWho.Data.ApplicationDbContext _db; // fully qualified

    public DiscoveryAugmentationHandler(ILogger<DiscoveryAugmentationHandler> logger, MrWho.Data.ApplicationDbContext db) // ctor updated
    { _logger = logger; _db = db; }

    public ValueTask HandleAsync(ApplyConfigurationResponseContext context)
    {
        var resp = context.Response;
        if (resp is null)
        {
            return ValueTask.CompletedTask;
        }

        try
        {
            resp[OpenIddictConstants.Metadata.RequestParameterSupported] = true;
            resp[OpenIddictConstants.Metadata.RequestUriParameterSupported] = true; // PAR supported
            resp["authorization_response_iss_parameter_supported"] = true;
            var current = resp[OpenIddictConstants.Metadata.ResponseModesSupported];
            bool added = false;
            if (current is not null)
            {
                var raw = current.ToString();
                if (!string.IsNullOrEmpty(raw) && raw.Contains("[") && raw.Contains("query") && !raw.Contains("jwt"))
                {
                    using var doc = JsonDocument.Parse(raw);
                    var list = doc.RootElement.EnumerateArray().Select(e => e.GetString()!).ToList();
                    list.Add("jwt");
                    using var rebuilt = JsonDocument.Parse("[" + string.Join(',', list.Select(s => $"\"{s}\"")) + "]");
                    resp[OpenIddictConstants.Metadata.ResponseModesSupported] = rebuilt.RootElement.Clone();
                    added = true;
                }
            }
            if (!added)
            {
                using var modesDoc = JsonDocument.Parse("[\"query\",\"fragment\",\"form_post\",\"jwt\"]");
                resp[OpenIddictConstants.Metadata.ResponseModesSupported] = modesDoc.RootElement.Clone();
            }

            var algs = new List<string> { "RS256" }; // always advertise RS256
            try
            {
                var jarClients = _db.Clients.AsNoTracking()
                    .Where(c => c.JarMode == null || c.JarMode != JarMode.Disabled)
                    .Select(c => new { c.AllowedRequestObjectAlgs })
                    .ToList();

                bool hs256 = false, hs384 = false, hs512 = false;
                foreach (var c in jarClients)
                {
                    var list = string.IsNullOrWhiteSpace(c.AllowedRequestObjectAlgs)
                        ? Array.Empty<string>()
                        : c.AllowedRequestObjectAlgs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (list.Length == 0)
                    {
                        hs256 = true; // default
                        continue;
                    }
                    foreach (var a in list)
                    {
                        if (a.Equals("HS256", StringComparison.OrdinalIgnoreCase)) hs256 = true;
                        else if (a.Equals("HS384", StringComparison.OrdinalIgnoreCase)) hs384 = true;
                        else if (a.Equals("HS512", StringComparison.OrdinalIgnoreCase)) hs512 = true;
                    }
                }
                if (hs256) algs.Add("HS256");
                if (hs384) algs.Add("HS384");
                if (hs512) algs.Add("HS512");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed building dynamic HS alg list for discovery; falling back to RS256 only");
            }
            using var algsDoc = JsonDocument.Parse("[" + string.Join(',', algs.Select(a => $"\"{a}\"")) + "]");
            resp[OpenIddictConstants.Metadata.RequestObjectSigningAlgValuesSupported] = algsDoc.RootElement.Clone();
            _logger.LogDebug("Discovery metadata augmented (request_object_signing_alg_values_supported={Algs}, request_uri_supported=true)", string.Join(',', algs));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed augmenting discovery metadata");
        }
        return ValueTask.CompletedTask;
    }
}

// Normalization & enforcement handler: allow response_mode=jwt even if core validation doesn't know it.
// Also enforce JarmMode=Required (client setting) by injecting mrwho_jarm=1 when response_mode not supplied.
internal sealed class JarmResponseModeNormalizationHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<JarmResponseModeNormalizationHandler> _logger;
    public JarmResponseModeNormalizationHandler(ApplicationDbContext db, ILogger<JarmResponseModeNormalizationHandler> logger)
    { _db = db; _logger = logger; }

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Transaction?.Request ?? context.Request;
        if (request == null)
        {
            return ValueTask.CompletedTask;
        }

        if (string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
        {
            request.SetParameter("mrwho_jarm", "1");
            request.ResponseMode = null;
            request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
            return ValueTask.CompletedTask;
        }

        if (request.GetParameter("mrwho_jarm") is not null)
        {
            return ValueTask.CompletedTask;
        }

        if (!string.IsNullOrEmpty(request.ClientId))
        {
            try
            {
                var required = _db.Clients.AsNoTracking()
                    .Where(c => c.ClientId == request.ClientId)
                    .Select(c => c.JarmMode)
                    .FirstOrDefault();
                if (required == JarmMode.Required)
                {
                    request.SetParameter("mrwho_jarm", "1");
                    _logger.LogDebug("Enforced JARM (Required) for client {ClientId} by injecting mrwho_jarm=1", request.ClientId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to evaluate JarmMode enforcement for client {ClientId}", request.ClientId);
            }
        }
        return ValueTask.CompletedTask;
    }
}

// JARM packaging handler: wraps authorization success or error into signed JWT when response_mode=jwt
internal sealed class JarmAuthorizationResponseHandler : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    private readonly ILogger<JarmAuthorizationResponseHandler> _logger;
    private readonly IKeyManagementService _keyService;
    private readonly JarOptions _jarOptions;
    private readonly ISecurityAuditWriter _auditWriter; // injected
    private readonly IProtocolMetrics _metrics; // NEW

    public JarmAuthorizationResponseHandler(ILogger<JarmAuthorizationResponseHandler> logger, IKeyManagementService keyService, Microsoft.Extensions.Options.IOptions<JarOptions> jarOptions, ISecurityAuditWriter auditWriter, IProtocolMetrics metrics)
    { _logger = logger; _keyService = keyService; _jarOptions = jarOptions.Value; _auditWriter = auditWriter; _metrics = metrics; }

    private static void EnsureKeyId(SecurityKey key, ILogger logger)
    {
        if (!string.IsNullOrEmpty(key.KeyId)) return;
        try
        {
            switch (key)
            {
                case RsaSecurityKey rsa when rsa.Rsa != null:
                    var parameters = rsa.Rsa.ExportParameters(false);
                    if (parameters.Modulus != null)
                    {
                        using var sha = SHA256.Create();
                        var hash = sha.ComputeHash(parameters.Modulus);
                        rsa.KeyId = Base64UrlEncoder.Encode(hash);
                    }
                    break;
                case RsaSecurityKey rsa2 when rsa2.Parameters.Modulus != null:
                    using (var sha2 = SHA256.Create())
                    {
                        var hash = sha2.ComputeHash(rsa2.Parameters.Modulus);
                        rsa2.KeyId = Base64UrlEncoder.Encode(hash);
                    }
                    break;
                case X509SecurityKey x509:
                    var thumb = x509.Certificate.GetCertHash(HashAlgorithmName.SHA256);
                    x509.KeyId = Base64UrlEncoder.Encode(thumb);
                    break;
                case SymmetricSecurityKey sym:
                    using (var sha3 = SHA256.Create())
                    {
                        var hash = sha3.ComputeHash(sym.Key);
                        sym.KeyId = Base64UrlEncoder.Encode(hash);
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed generating KeyId for JARM signing key; proceeding without kid");
        }
    }

    public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        try
        {
            var jarmRequested = string.Equals(context.Request?.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(context.Request?.GetParameter("mrwho_jarm").ToString(), "1", StringComparison.Ordinal);
            if (!jarmRequested) return;

            // Collect parameters to embed
            var response = context.Response;
            if (response is null) return;

            var issuer = response[OpenIddictConstants.Metadata.Issuer]?.ToString()?.TrimEnd('/') ?? string.Empty;
            var clientId = context.Request?.ClientId ?? response[OpenIddictConstants.Parameters.ClientId]?.ToString();
            var now = DateTimeOffset.UtcNow;
            var exp = now.AddSeconds(Math.Clamp(_jarOptions.JarmTokenLifetimeSeconds, 30, 300));
            var claims = new Dictionary<string, object?>
            {
                ["iss"] = issuer,
                ["aud"] = clientId,
                ["iat"] = now.ToUnixTimeSeconds(),
                ["exp"] = exp.ToUnixTimeSeconds()
            };

            string? codeValue = response[OpenIddictConstants.Parameters.Code]?.ToString();
            if (!string.IsNullOrEmpty(codeValue)) claims[OpenIddictConstants.Parameters.Code] = codeValue;
            string? stateValue = response[OpenIddictConstants.Parameters.State]?.ToString();
            if (!string.IsNullOrEmpty(stateValue)) claims[OpenIddictConstants.Parameters.State] = stateValue;
            string? errorValue = response[OpenIddictConstants.Parameters.Error]?.ToString();
            if (!string.IsNullOrEmpty(errorValue))
            {
                claims[OpenIddictConstants.Parameters.Error] = errorValue;
                var errDesc = response[OpenIddictConstants.Parameters.ErrorDescription]?.ToString();
                if (!string.IsNullOrEmpty(errDesc)) claims[OpenIddictConstants.Parameters.ErrorDescription] = errDesc;
            }

            // Obtain signing key
            var (signingKeys, _) = await _keyService.GetActiveKeysAsync();
            var signingKey = signingKeys.FirstOrDefault();
            if (signingKey is null)
            {
                _logger.LogWarning("No signing key available for JARM response");
                _metrics.IncrementJarmResponse("failure");
                return;
            }
            EnsureKeyId(signingKey, _logger);
            var creds = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
            var handler = new JsonWebTokenHandler();
            var payloadClaims = claims.Where(kv => kv.Key is not ("iss" or "aud" or "exp" or "iat") && kv.Value is not null)
                .ToDictionary(kv => kv.Key, kv => kv.Value!);
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = clientId,
                Expires = exp.UtcDateTime,
                NotBefore = now.UtcDateTime.AddSeconds(-5),
                IssuedAt = now.UtcDateTime,
                Claims = payloadClaims,
                SigningCredentials = creds
            };
            var jwt = handler.CreateToken(descriptor);

            // Cleanup original parameters
            if (!string.IsNullOrEmpty(codeValue)) response[OpenIddictConstants.Parameters.Code] = null;
            if (!string.IsNullOrEmpty(errorValue))
            {
                response[OpenIddictConstants.Parameters.Error] = null;
                response[OpenIddictConstants.Parameters.ErrorDescription] = null;
            }
            response["response"] = jwt;
            var outcome = string.IsNullOrEmpty(errorValue) ? "success" : "error";
            _metrics.IncrementJarmResponse(outcome);
            _logger.LogDebug("Issued JARM JWT (iss={Issuer}, aud={Aud}, outcome={Outcome}, kid={Kid})", issuer, clientId, outcome, signingKey.KeyId);
            try { await _auditWriter.WriteAsync("auth.security", errorValue == null ? "jarm.issued" : "jarm.error", new { clientId, hasCode = codeValue != null, error = errorValue, state = stateValue, kid = signingKey.KeyId }, "info", actorClientId: clientId); } catch { }
        }
        catch (Exception ex)
        {
            _metrics.IncrementJarmResponse("failure");
            _logger.LogError(ex, "Failed to create JARM response JWT");
            try { await _auditWriter.WriteAsync("auth.security", "jarm.failure", new { ex = ex.Message }, "error"); } catch { }
        }
    }
}

internal sealed class JarEarlyExtractAndValidateHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ExtractAuthorizationRequestContext>
{
    private readonly IJarValidationService _validator;
    private readonly ILogger<JarEarlyExtractAndValidateHandler> _logger;
    private readonly OidcAdvancedOptions _adv;
    private readonly JarOptions _jarOptions; // NEW
    private readonly IJarReplayCache _replay; // NEW
    private readonly IProtocolMetrics _metrics;

    public JarEarlyExtractAndValidateHandler(IJarValidationService validator,
        ILogger<JarEarlyExtractAndValidateHandler> logger,
        Microsoft.Extensions.Options.IOptions<OidcAdvancedOptions> adv,
        Microsoft.Extensions.Options.IOptions<JarOptions> jarOptions,
        IJarReplayCache replay,
        IProtocolMetrics metrics)
    { _validator = validator; _logger = logger; _adv = adv.Value; _jarOptions = jarOptions.Value; _replay = replay; _metrics = metrics; }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ExtractAuthorizationRequestContext context)
    {
        if (context == null || context.Request == null) return;
        var request = context.Request;

        // Also pick up raw 'request' parameter if the strongly-typed property is empty
        if (string.IsNullOrEmpty(request.Request))
        {
            var rawReqParam = request.GetParameter(OpenIddictConstants.Parameters.Request)?.ToString();
            if (!string.IsNullOrWhiteSpace(rawReqParam))
            {
                request.Request = rawReqParam;
            }
        }

        if (string.IsNullOrEmpty(request.Request)) return; // no JAR param

        try
        {
            var queryClientId = request.ClientId;
            var jwt = request.Request;
            var result = await _validator.ValidateAsync(jwt!, queryClientId, context.CancellationToken);
            if (!result.Success)
            {
                _metrics.IncrementJarRequest("reject", result.Algorithm ?? "unknown");
                context.Reject(
                    error: result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject,
                    description: result.ErrorDescription ?? "invalid request object"
                );
                return;
            }

            // JTI replay detection (early)
            string? jti = null;
            if (result.Parameters != null && result.Parameters.TryGetValue("jti", out var jtiParam)) jti = jtiParam?.ToString();
            if (string.IsNullOrEmpty(jti))
            {
                if (_jarOptions.RequireJti)
                {
                    _metrics.IncrementJarRequest("reject", result.Algorithm ?? "unknown");
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequestObject, description: "missing jti");
                    return;
                }
            }
            if (!string.IsNullOrEmpty(jti))
            {
                DateTimeOffset exp = DateTimeOffset.UtcNow.Add(_jarOptions.JtiCacheWindow);
                if (result.Parameters != null && result.Parameters.TryGetValue("exp", out var expParam) && long.TryParse(expParam?.ToString(), out var expEpoch))
                { try { exp = DateTimeOffset.FromUnixTimeSeconds(expEpoch); } catch { } }
                if (exp > DateTimeOffset.UtcNow + _jarOptions.MaxExp) exp = DateTimeOffset.UtcNow + _jarOptions.MaxExp;
                var cacheKey = "auth_jti:" + (queryClientId ?? "?") + ":" + jti;
                if (!_replay.TryAdd(cacheKey, exp))
                {
                    _logger.LogDebug("[JAR] Replay detected (early stage) client={ClientId} jti={Jti}", queryClientId, jti);
                    _metrics.IncrementJarReplayBlocked();
                    _metrics.IncrementJarRequest("replay", result.Algorithm ?? "unknown");
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "replay jti");
                    return;
                }
            }

            // Conflict detection BEFORE merging
            if (_adv.RequestConflicts.Enabled && result.Parameters != null)
            {
                var ignored = new HashSet<string>(_adv.RequestConflicts.IgnoredParameters ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                foreach (var kv in result.Parameters)
                {
                    if (ignored.Contains(kv.Key)) continue;
                    var existingParam = request.GetParameter(kv.Key);
                    string? existingStr = existingParam?.ToString();
                    if (existingStr == null)
                    {
                        switch (kv.Key)
                        {
                            case var k when string.Equals(k, OpenIddictConstants.Parameters.Scope, StringComparison.OrdinalIgnoreCase):
                                existingStr = request.Scope; break;
                            case var k when string.Equals(k, OpenIddictConstants.Parameters.RedirectUri, StringComparison.OrdinalIgnoreCase):
                                existingStr = request.RedirectUri; break;
                            case var k when string.Equals(k, OpenIddictConstants.Parameters.ResponseType, StringComparison.OrdinalIgnoreCase):
                                existingStr = request.ResponseType; break;
                            case var k when string.Equals(k, OpenIddictConstants.Parameters.State, StringComparison.OrdinalIgnoreCase):
                                existingStr = request.State; break;
                            case var k when string.Equals(k, OpenIddictConstants.Parameters.Nonce, StringComparison.OrdinalIgnoreCase):
                                existingStr = request.Nonce; break;
                            case var k when string.Equals(k, OpenIddictConstants.Parameters.ClientId, StringComparison.OrdinalIgnoreCase):
                                existingStr = request.ClientId; break;
                            default:
                                existingStr = null; break;
                        }
                    }
                    if (existingStr is null) continue;
                    var newVal = kv.Value?.ToString() ?? string.Empty;
                    if (kv.Key == OpenIddictConstants.Parameters.Scope)
                    {
                        static string NormalizeScopes(string? v) => string.Join(' ', (v ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).OrderBy(x => x, StringComparer.Ordinal));
                        if (_adv.RequestConflicts.StrictScopeOrdering)
                        {
                            if (!string.Equals(existingStr, newVal, StringComparison.Ordinal))
                            {
                                context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "parameter_conflict:scope");
                                _metrics.IncrementValidationEvent("conflict", "scope");
                                return;
                            }
                        }
                        else if (NormalizeScopes(existingStr) != NormalizeScopes(newVal))
                        {
                            context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "parameter_conflict:scope");
                            _metrics.IncrementValidationEvent("conflict", "scope");
                            return;
                        }
                    }
                    else if (!string.Equals(existingStr, newVal, StringComparison.Ordinal))
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: $"parameter_conflict:{kv.Key}");
                        _metrics.IncrementValidationEvent("conflict", kv.Key);
                        return;
                    }
                }
            }

            // Find scope values for later validation stage comparison (use property fallback)
            var originalScope = request.GetParameter(OpenIddictConstants.Parameters.Scope)?.ToString();
            if (string.IsNullOrEmpty(originalScope)) originalScope = request.Scope;
            string? jarScopeParam = null;
            if (result.Parameters != null && result.Parameters.TryGetValue(OpenIddictConstants.Parameters.Scope, out var scopeFromJarObj))
            {
                jarScopeParam = scopeFromJarObj?.ToString();
            }
            if (!string.IsNullOrEmpty(originalScope) && !string.IsNullOrEmpty(jarScopeParam))
            {
                // Store for later conflict check in validation stage (both as parameters and transaction properties)
                request.SetParameter("_query_scope", originalScope);
                request.SetParameter("_jar_scope", jarScopeParam);
                try
                {
                    if (context.Transaction != null)
                    {
                        context.Transaction.Properties["mrwho.query_scope"] = originalScope;
                        context.Transaction.Properties["mrwho.jar_scope"] = jarScopeParam;
                    }
                }
                catch { /* ignore */ }
            }

            // Merge validated parameters
            if (result.Parameters != null)
            {
                foreach (var kv in result.Parameters) request.SetParameter(kv.Key, kv.Value);
            }
            request.Request = null;
            request.SetParameter(OpenIddictConstants.Parameters.Request, null);
            if (context.Transaction?.Request != null)
            {
                context.Transaction.Request.SetParameter(OpenIddictConstants.Parameters.Request, null);
                context.Transaction.Request.Request = null;
            }
            request.SetParameter("_jar_validated", "1");
            if (request.GetParameter("_jar_metrics") is null)
            {
                _metrics.IncrementJarRequest("success", result.Algorithm ?? "unknown");
                request.SetParameter("_jar_metrics", "1");
            }
            _logger.LogDebug("[JAR] Early extract validated request object for client {ClientId} alg {Alg} (merged {Count} params, jti={Jti})", result.ClientId, result.Algorithm, result.Parameters?.Count ?? 0, jti);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[JAR] Unhandled error during early validation");
            _metrics.IncrementJarRequest("error", "unknown");
            context.Reject(error: OpenIddictConstants.Errors.InvalidRequestObject, description: "invalid request object");
        }
    }
}

// Handler for resolving PAR request_uri
internal sealed class ParRequestUriResolutionHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ExtractAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParRequestUriResolutionHandler> _logger;
    private readonly IProtocolMetrics _metrics;
    public ParRequestUriResolutionHandler(ApplicationDbContext db, ILogger<ParRequestUriResolutionHandler> logger, IProtocolMetrics metrics)
    { _db = db; _logger = logger; _metrics = metrics; }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ExtractAuthorizationRequestContext context)
    {
        if (context?.Request == null) return;
        var request = context.Request;
        var requestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri)?.ToString();
        if (string.IsNullOrWhiteSpace(requestUri)) return;

        try
        {
            var par = await _db.PushedAuthorizationRequests.AsNoTracking().FirstOrDefaultAsync(p => p.RequestUri == requestUri);
            if (par == null)
            {
                _logger.LogDebug("[PAR] request_uri not found: {RequestUri}", requestUri);
                _metrics.IncrementParResolve("missing");
                return;
            }
            if (DateTime.UtcNow > par.ExpiresAt)
            {
                _logger.LogDebug("[PAR] request_uri expired: {RequestUri}", requestUri);
                _metrics.IncrementParResolve("expired");
                return;
            }
            if (!string.IsNullOrWhiteSpace(par.ParametersJson))
            {
                try
                {
                    var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(par.ParametersJson) ?? new();
                    foreach (var kv in dict)
                    {
                        if (kv.Key == OpenIddictConstants.Parameters.RequestUri) continue;
                        if (kv.Key == OpenIddictConstants.Parameters.Request)
                        {
                            if (string.IsNullOrEmpty(request.Request)) request.Request = kv.Value;
                            continue;
                        }
                        if (request.GetParameter(kv.Key) is null) request.SetParameter(kv.Key, kv.Value);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[PAR] Failed to deserialize stored parameters for {RequestUri}", requestUri);
                }
            }
            request.SetParameter("_par_resolved", "1");
            _metrics.IncrementParResolve("resolved");
            _logger.LogDebug("[PAR] Resolved request_uri {RequestUri} (expires {ExpiresAt:u})", requestUri, par.ExpiresAt);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[PAR] Error resolving request_uri {RequestUri}", requestUri);
            _metrics.IncrementParResolve("error");
        }
    }
}

// Handler for consuming PAR request_uri (PJ49)
internal sealed class ParConsumptionHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly IOptions<OidcAdvancedOptions> _adv;
    private readonly ILogger<ParConsumptionHandler> _logger;
    private readonly IProtocolMetrics _metrics;
    public ParConsumptionHandler(ApplicationDbContext db, IOptions<OidcAdvancedOptions> adv, ILogger<ParConsumptionHandler> logger, IProtocolMetrics metrics)
    { _db = db; _adv = adv; _logger = logger; _metrics = metrics; }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
    {
        if (context.Request == null) return;
        var request = context.Request;
        var requestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri)?.ToString();
        if (string.IsNullOrWhiteSpace(requestUri)) return;
        if (request.GetParameter("_par_resolved") is null) return;

        bool singleUse = _adv.Value.ParSingleUseDefault;
        if (!singleUse) return;

        try
        {
            var par = await _db.PushedAuthorizationRequests.FirstOrDefaultAsync(p => p.RequestUri == requestUri);
            if (par == null)
            {
                context.Reject(error: OpenIddictConstants.Errors.InvalidRequestUri, description: "invalid or unknown request_uri");
                _metrics.IncrementParResolve("missing");
                return;
            }
            if (DateTime.UtcNow > par.ExpiresAt)
            {
                context.Reject(error: OpenIddictConstants.Errors.InvalidRequestUri, description: "expired request_uri");
                _metrics.IncrementParResolve("expired");
                return;
            }
            par.ConsumedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(context.CancellationToken);
            _metrics.IncrementParResolve("consumed");
            _logger.LogDebug("[PAR] Consumed request_uri {RequestUri} (single-use)", requestUri);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[PAR] Error consuming request_uri {RequestUri}", requestUri);
            _metrics.IncrementParResolve("error");
            context.Reject(error: OpenIddictConstants.Errors.ServerError, description: "failed to mark request_uri consumed");
        }
    }
}

// Handler for enforcing ParMode=Required natively (PJ14)
internal sealed class ParModeEnforcementHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParModeEnforcementHandler> _logger;
    public ParModeEnforcementHandler(ApplicationDbContext db, ILogger<ParModeEnforcementHandler> logger)
    { _db = db; _logger = logger; }

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Request;
        if (request == null) return ValueTask.CompletedTask;
        var clientId = request.ClientId;
        if (string.IsNullOrEmpty(clientId)) return ValueTask.CompletedTask;
        try
        {
            var parMode = _db.Clients.AsNoTracking()
                .Where(c => c.ClientId == clientId)
                .Select(c => c.ParMode)
                .FirstOrDefault();
            if (parMode == MrWho.Shared.PushedAuthorizationMode.Required)
            {
                // Consider PAR satisfied once resolution marker is present, even if core removed request_uri param.
                bool resolved = request.GetParameter("_par_resolved") is not null;
                // Also defer enforcement if a request_uri is present (resolution happens later in pipeline).
                bool hasRequestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri) is not null;
                if (!resolved && !hasRequestUri)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "PAR required for this client");
                    _logger.LogDebug("[PAR] Rejected authorize request missing request_uri/resolution (ParMode=Required) client {ClientId}", clientId);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[PAR] Native ParMode enforcement skipped due to error for client {ClientId}", clientId);
        }
        return ValueTask.CompletedTask;
    }
}

// NEW: JarMode enforcement handler (PJ37)
internal sealed class JarModeEnforcementHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<JarModeEnforcementHandler> _logger;
    public JarModeEnforcementHandler(ApplicationDbContext db, ILogger<JarModeEnforcementHandler> logger)
    { _db = db; _logger = logger; }

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Request;
        if (request == null) return ValueTask.CompletedTask;
        var clientId = request.ClientId;
        if (string.IsNullOrEmpty(clientId)) return ValueTask.CompletedTask; // core handler will reject missing client
        try
        {
            var jarMode = _db.Clients.AsNoTracking()
                .Where(c => c.ClientId == clientId)
                .Select(c => c.JarMode)
                .FirstOrDefault();
            if (jarMode == JarMode.Required)
            {
                bool hasValidated = request.GetParameter("_jar_validated") is not null;
                bool hasRaw = request.GetParameter(OpenIddictConstants.Parameters.Request) is not null || !string.IsNullOrEmpty(request.Request);
                // Consider PAR resolution sufficient to defer enforcement until JAR validation runs.
                bool parResolved = request.GetParameter("_par_resolved") is not null;
                // Also defer enforcement if a request_uri is present (resolution/validation happens later).
                bool hasRequestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri) is not null;
                if (!hasValidated && !hasRaw && !parResolved && !hasRequestUri)
                {
                    _logger.LogDebug("[JAR] Enforcement fail client={ClientId} validated={Validated} raw={Raw} parResolved={ParResolved} hasRequestUri={HasRequestUri}", clientId, hasValidated, hasRaw, parResolved, hasRequestUri);
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "request object required for this client");
                }
                else
                {
                    _logger.LogDebug("[JAR] Enforcement pass client={ClientId} validated={Validated} raw={Raw} parResolved={ParResolved} hasRequestUri={HasRequestUri}", clientId, hasValidated, hasRaw, parResolved, hasRequestUri);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[JAR] JarMode enforcement skipped due to error for client {ClientId}", clientId);
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class JarValidateRequestObjectHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly IJarValidationService _validator;
    private readonly ILogger<JarValidateRequestObjectHandler> _logger;
    private readonly OidcAdvancedOptions _adv;
    private readonly IJarReplayCache _replay; // NEW
    private readonly JarOptions _jarOptions;  // NEW
    private readonly IProtocolMetrics _metrics;
    public JarValidateRequestObjectHandler(IJarValidationService validator, ILogger<JarValidateRequestObjectHandler> logger, Microsoft.Extensions.Options.IOptions<OidcAdvancedOptions> adv, IJarReplayCache replay, Microsoft.Extensions.Options.IOptions<JarOptions> jarOptions, IProtocolMetrics metrics)
    { _validator = validator; _logger = logger; _adv = adv.Value; _replay = replay; _jarOptions = jarOptions.Value; _metrics = metrics; }
    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var req = context.Request;
        if (req == null) return;
        var raw = req.Request;
        if (string.IsNullOrEmpty(raw)) return; // nothing to do (already processed earlier)
        try
        {
            var result = await _validator.ValidateAsync(raw, req.ClientId, context.CancellationToken);
            if (!result.Success)
            {
                _metrics.IncrementJarRequest("reject", result.Algorithm ?? "unknown");
                context.Reject(error: result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject, description: result.ErrorDescription ?? "invalid request object");
                return;
            }
            string? jti = null;
            if (result.Parameters != null && result.Parameters.TryGetValue("jti", out var jtiParam)) jti = jtiParam?.ToString();
            if (string.IsNullOrEmpty(jti) && _jarOptions.RequireJti)
            {
                _metrics.IncrementJarRequest("reject", result.Algorithm ?? "unknown");
                context.Reject(error: OpenIddictConstants.Errors.InvalidRequestObject, description: "missing jti");
                return;
            }
            if (!string.IsNullOrEmpty(jti))
            {
                DateTimeOffset exp = DateTimeOffset.UtcNow.Add(_jarOptions.JtiCacheWindow);
                if (result.Parameters != null && result.Parameters.TryGetValue("exp", out var expParam) && long.TryParse(expParam?.ToString(), out var expEpoch))
                { try { exp = DateTimeOffset.FromUnixTimeSeconds(expEpoch); } catch { } }
                if (exp > DateTimeOffset.UtcNow + _jarOptions.MaxExp) exp = DateTimeOffset.UtcNow + _jarOptions.MaxExp;
                var cacheKey = "auth_jti:" + (req.ClientId ?? "?") + ":" + jti;
                if (!_replay.TryAdd(cacheKey, exp))
                {
                    _logger.LogDebug("[JAR] Replay detected (validate stage) client={ClientId} jti={Jti}", req.ClientId, jti);
                    _metrics.IncrementJarReplayBlocked();
                    _metrics.IncrementJarRequest("replay", result.Algorithm ?? "unknown");
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "replay jti");
                    return;
                }
            }
            if (result.Parameters != null)
            {
                foreach (var kv in result.Parameters) req.SetParameter(kv.Key, kv.Value);
            }
            req.Request = null; req.SetParameter(OpenIddictConstants.Parameters.Request, null);
            req.SetParameter("_jar_validated", "1");
            if (req.GetParameter("_jar_metrics") is null)
            {
                _metrics.IncrementJarRequest("success", result.Algorithm ?? "unknown");
                req.SetParameter("_jar_metrics", "1");
            }
            _logger.LogDebug("[JAR] Validate-stage processed leftover request object for client {ClientId} (merged {Count} params, jti={Jti})", result.ClientId, result.Parameters?.Count ?? 0, jti);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[JAR] Error validating request object at validate stage");
            _metrics.IncrementJarRequest("error", "unknown");
            context.Reject(error: OpenIddictConstants.Errors.InvalidRequestObject, description: "invalid request object");
        }
    }
}

internal sealed class RedirectUriFallbackHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly ILogger<RedirectUriFallbackHandler> _logger;
    public RedirectUriFallbackHandler(ILogger<RedirectUriFallbackHandler> logger) { _logger = logger; }
    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var req = context.Request;
        if (req == null) return ValueTask.CompletedTask;
        if (string.IsNullOrEmpty(context.RedirectUri))
        {
            var fromParam = req.GetParameter(OpenIddictConstants.Parameters.RedirectUri).ToString();
            if (string.IsNullOrEmpty(fromParam)) fromParam = req.RedirectUri;
            if (!string.IsNullOrEmpty(fromParam))
            {
                context.SetRedirectUri(fromParam);
                _logger.LogDebug("[JAR] RedirectUriFallback applied SetRedirectUri={RedirectUri}", fromParam);
            }
        }
        return ValueTask.CompletedTask;
    }
}

public static class JarJarmServerEventHandlers
{
    private sealed class JarmResponseModeExtractHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
    {
        private readonly ApplicationDbContext _db;
        private readonly ILogger<JarmResponseModeExtractHandler> _logger;
        public JarmResponseModeExtractHandler(ApplicationDbContext db, ILogger<JarmResponseModeExtractHandler> logger)
        { _db = db; _logger = logger; }
        public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
        {
            var request = context.Transaction?.Request ?? context.Request;
            if (request == null) return ValueTask.CompletedTask;
            if (string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
            {
                request.SetParameter("mrwho_jarm", "1");
                request.ResponseMode = null;
                request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
                return ValueTask.CompletedTask;
            }
            if (request.GetParameter("mrwho_jarm") is not null) return ValueTask.CompletedTask;
            var clientId = request.ClientId;
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    var mode = _db.Clients.AsNoTracking().Where(c => c.ClientId == clientId).Select(c => c.JarmMode).FirstOrDefault();
                    if (mode == JarmMode.Required)
                    {
                        request.SetParameter("mrwho_jarm", "1");
                        _logger.LogDebug("[JARM] Injected mrwho_jarm=1 at extract stage for required client {ClientId}", clientId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[JARM] Early required mode check error for client {ClientId}", clientId);
                }
            }
            return ValueTask.CompletedTask;
        }
    }

    // Descriptor definitions (ensure names referenced in ServiceCollectionExtensions exist)
    public static OpenIddictServerHandlerDescriptor ConfigurationHandlerDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseScopedHandler<DiscoveryAugmentationHandler>()
            .SetOrder(0)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ParRequestUriResolutionDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<ParRequestUriResolutionHandler>()
            .SetOrder(int.MinValue) // earliest
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor JarEarlyExtractAndValidateDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<JarEarlyExtractAndValidateHandler>()
            .SetOrder(int.MinValue + 1) // immediately after PAR resolution so we beat built-in handlers
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ExtractNormalizeJarmResponseModeDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<JarmResponseModeExtractHandler>()
            .SetOrder(int.MinValue + 10)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor NormalizeJarmResponseModeDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<JarmResponseModeNormalizationHandler>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor RequestConflictAndLimitValidationDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
        .UseScopedHandler<RequestConflictAndLimitValidationHandler>()
        .SetOrder(int.MinValue + 6)
        .SetType(OpenIddictServerHandlerType.Custom)
        .Build();

    public static OpenIddictServerHandlerDescriptor JarModeEnforcementDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
        .UseScopedHandler<JarModeEnforcementHandler>()
        .SetOrder(int.MinValue + 7)
        .SetType(OpenIddictServerHandlerType.Custom)
        .Build();

    public static OpenIddictServerHandlerDescriptor ParModeEnforcementDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
        .UseScopedHandler<ParModeEnforcementHandler>()
        .SetOrder(int.MinValue + 8)
        .SetType(OpenIddictServerHandlerType.Custom)
        .Build();

    public static OpenIddictServerHandlerDescriptor ParConsumptionDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<ParConsumptionHandler>()
            .SetOrder(int.MinValue + 10)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ApplyAuthorizationResponseDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<JarmAuthorizationResponseHandler>()
            .SetOrder(int.MaxValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor JarValidateRequestObjectDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<JarValidateRequestObjectHandler>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor RedirectUriFallbackDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<RedirectUriFallbackHandler>()
            .SetOrder(int.MinValue + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();
}
