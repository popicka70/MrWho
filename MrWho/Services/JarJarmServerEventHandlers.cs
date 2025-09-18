using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using MrWho.Data;
using MrWho.Models;
using MrWho.Options;
using MrWho.Shared;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace MrWho.Services;

public class JarOptions
{
    public const string SectionName = "Jar";
    public int MaxRequestObjectBytes { get; set; } = 4096;
    public bool RequireJti { get; set; } = true;
    public TimeSpan JtiCacheWindow { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan MaxExp { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
    public int JarmTokenLifetimeSeconds { get; set; } = 120;
    public int ClaimCountLimit { get; set; } = 0;
    public int ClaimValueMaxLength { get; set; } = 0;
    public bool EnforceQueryConsistency { get; set; } = false;
}

public interface IJarReplayCache { bool TryAdd(string key, DateTimeOffset expiresUtc); }
public sealed class InMemoryJarReplayCache : IJarReplayCache
{
    private readonly IMemoryCache _cache;
    public InMemoryJarReplayCache(IMemoryCache cache) => _cache = cache;
    public bool TryAdd(string key, DateTimeOffset expiresUtc)
    {
        if (_cache.TryGetValue(key, out _)) return false;
        var ttl = expiresUtc - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromSeconds(1);
        _cache.Set(key, 1, ttl);
        return true;
    }
}

internal sealed class RequestConflictAndLimitValidationHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly IOptions<OidcAdvancedOptions> _adv;
    private readonly ILogger<RequestConflictAndLimitValidationHandler> _logger;
    private readonly IProtocolMetrics _metrics;

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
        "_mrwho_max_params","_par_request_uri","_jar_metrics","mrwho_jarm"
    };

    private static readonly HashSet<string> _internalParams = new(StringComparer.OrdinalIgnoreCase)
    {
        "_query_scope","_jar_scope","_mrwho_max_params","_par_resolved","_par_request_uri","_jar_validated","_jar_metrics","mrwho_jarm"
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
            string? queryScope = request.GetParameter("_query_scope")?.ToString();
            string? jarScope = request.GetParameter("_jar_scope")?.ToString();
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

            var parameterNames = request.GetParameters()
                .Select(p => p.Key)
                .Where(k => !_internalParams.Contains(k))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (adv.RequestLimits is { } limits)
            {
                int? effectiveMaxParams = limits.MaxParameters;
                try
                {
                    var testMode = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase);
                    if (testMode)
                    {
                        var overrideParam = request.GetParameter("_mrwho_max_params")?.ToString();
                        if (!string.IsNullOrWhiteSpace(overrideParam) && int.TryParse(overrideParam, out var parsed) && parsed >= 0)
                            effectiveMaxParams = parsed;
                    }
                }
                catch { }

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
                    // Skip heavy parameters from aggregate bytes counting to avoid penalizing JAR/PAR machinery.
                    if (name.Equals(OpenIddictConstants.Parameters.Request, StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(OpenIddictConstants.Parameters.RequestUri, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
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
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Request conflict/limit handler encountered error; continuing (fail-open)");
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class DiscoveryAugmentationHandler : IOpenIddictServerHandler<ApplyConfigurationResponseContext>
{
    private readonly ILogger<DiscoveryAugmentationHandler> _logger;
    private readonly ApplicationDbContext _db;
    public DiscoveryAugmentationHandler(ILogger<DiscoveryAugmentationHandler> logger, ApplicationDbContext db)
    { _logger = logger; _db = db; }

    public ValueTask HandleAsync(ApplyConfigurationResponseContext context)
    {
        var resp = context.Response;
        if (resp is null) return ValueTask.CompletedTask;

        try
        {
            resp[OpenIddictConstants.Metadata.RequestParameterSupported] = true;
            resp[OpenIddictConstants.Metadata.RequestUriParameterSupported] = true;
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

            var algs = new List<string> { "RS256" };
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
                    if (list.Length == 0) { hs256 = true; continue; }
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
        { _logger.LogError(ex, "Failed augmenting discovery metadata"); }

        return ValueTask.CompletedTask;
    }
}

internal sealed class JarmResponseModeNormalizationHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<JarmResponseModeNormalizationHandler> _logger;
    public JarmResponseModeNormalizationHandler(ApplicationDbContext db, ILogger<JarmResponseModeNormalizationHandler> logger)
    { _db = db; _logger = logger; }

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Transaction?.Request ?? context.Request;
        if (request == null) return ValueTask.CompletedTask;

        try
        {
            var names = string.Join(',', request.GetParameters().Select(p => p.Key));
            _logger.LogDebug("[JARM-NORM] Incoming param names: {Names}; response_mode={Mode}; mrwho_jarm={MrWhoJarm}", names, request.ResponseMode, request.GetParameter("mrwho_jarm"));
        }
        catch { }

        if (string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
        {
            request.SetParameter("mrwho_jarm", "1");
            request.ResponseMode = null;
            request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
            _logger.LogDebug("[JARM-NORM] Normalized response_mode=jwt to mrwho_jarm=1");
            return ValueTask.CompletedTask;
        }

        if (request.GetParameter("mrwho_jarm") is not null) return ValueTask.CompletedTask;

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
                    _logger.LogDebug("[JARM-NORM] Enforced mrwho_jarm=1 (client requires JARM) clientId={ClientId}", request.ClientId);
                }
            }
            catch (Exception ex)
            { _logger.LogDebug(ex, "[JARM-NORM] Failed to evaluate JarmMode enforcement for client {ClientId}", request.ClientId); }
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class JarmAuthorizationResponseHandler : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    private readonly ILogger<JarmAuthorizationResponseHandler> _logger;
    private readonly IKeyManagementService _keyService;
    private readonly JarOptions _jarOptions;
    private readonly ISecurityAuditWriter _auditWriter;
    private readonly IProtocolMetrics _metrics;

    public JarmAuthorizationResponseHandler(ILogger<JarmAuthorizationResponseHandler> logger, IKeyManagementService keyService, IOptions<JarOptions> jarOptions, ISecurityAuditWriter auditWriter, IProtocolMetrics metrics)
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
        { logger.LogDebug(ex, "Failed generating KeyId for JARM signing key; proceeding without kid"); }
    }

    public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        try
        {
            var jarmRequested = string.Equals(context.Request?.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(context.Request?.GetParameter("mrwho_jarm").ToString(), "1", StringComparison.Ordinal);
            if (!jarmRequested) return;

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

internal sealed class JarEarlyExtractAndValidateHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    private readonly IJarValidationService _validator;
    private readonly ILogger<JarEarlyExtractAndValidateHandler> _logger;
    private readonly OidcAdvancedOptions _adv;
    private readonly JarOptions _jarOptions;
    private readonly IJarReplayCache _replay;
    private readonly IProtocolMetrics _metrics;

    public JarEarlyExtractAndValidateHandler(IJarValidationService validator, ILogger<JarEarlyExtractAndValidateHandler> logger, IOptions<OidcAdvancedOptions> adv, IOptions<JarOptions> jarOptions, IJarReplayCache replay, IProtocolMetrics metrics)
    { _validator = validator; _logger = logger; _adv = adv.Value; _jarOptions = jarOptions.Value; _replay = replay; _metrics = metrics; }

    public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        if (context == null || context.Request == null) return;
        var request = context.Request;

        // If middleware already validated JAR (sentinel present), skip to avoid double validation and jti replay.
        if (request.GetParameter("_jar_validated") is not null)
        {
            return;
        }

        if (string.IsNullOrEmpty(request.Request))
        {
            var rawReqParam = request.GetParameter(OpenIddictConstants.Parameters.Request)?.ToString();
            if (!string.IsNullOrWhiteSpace(rawReqParam)) request.Request = rawReqParam;
        }
        if (string.IsNullOrEmpty(request.Request)) return;

        try
        {
            var queryClientId = request.ClientId;
            var jwt = request.Request;
            var result = await _validator.ValidateAsync(jwt!, queryClientId, context.CancellationToken);
            if (!result.Success)
            {
                _metrics.IncrementJarRequest("reject", result.Algorithm ?? "unknown");
                context.Reject(error: result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject, description: result.ErrorDescription ?? "invalid request object");
                return;
            }

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
                { try { exp = DateTimeOffset.FromUnixTimeSeconds(expEpoch); } catch { }
                }
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

            // Merge validated parameters
            if (result.Parameters != null)
            {
                foreach (var kv in result.Parameters) request.SetParameter(kv.Key, kv.Value);
            }
            // Ensure strongly-typed RedirectUri is set if provided in the request object
            try
            {
                var redirectParam = request.GetParameter(OpenIddictConstants.Parameters.RedirectUri)?.ToString();
                if (string.IsNullOrWhiteSpace(request.RedirectUri) && !string.IsNullOrWhiteSpace(redirectParam))
                {
                    request.RedirectUri = redirectParam;
                    if (context.Transaction?.Request != null && string.IsNullOrWhiteSpace(context.Transaction.Request.RedirectUri))
                    {
                        context.Transaction.Request.RedirectUri = redirectParam;
                    }
                    _logger.LogDebug("[JAR] Applied redirect_uri from request object during extract: {Redirect}", redirectParam);
                }
            }
            catch { }

            // Preserve scope values for later conflict detection
            var originalScope = request.GetParameter(OpenIddictConstants.Parameters.Scope)?.ToString();
            if (string.IsNullOrEmpty(originalScope)) originalScope = request.Scope;
            string? jarScopeParam = null;
            if (result.Parameters != null && result.Parameters.TryGetValue(OpenIddictConstants.Parameters.Scope, out var scopeFromJarObj))
                jarScopeParam = scopeFromJarObj?.ToString();
            if (!string.IsNullOrEmpty(originalScope) && !string.IsNullOrEmpty(jarScopeParam))
            {
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
                catch { }
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

internal sealed class JarmResponseModeExtractHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<JarmResponseModeExtractHandler> _logger;
    public JarmResponseModeExtractHandler(ApplicationDbContext db, ILogger<JarmResponseModeExtractHandler> logger)
    { _db = db; _logger = logger; }

    public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        var request = context.Transaction?.Request ?? context.Request;
        if (request == null) return ValueTask.CompletedTask;

        try
        {
            var rm = request.ResponseMode;
            if (!string.IsNullOrEmpty(rm)) _logger.LogDebug("[JARM-EXTRACT] response_mode={Mode}", rm);
        }
        catch { }

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
                    _logger.LogDebug("[JARM-EXTRACT] Injected mrwho_jarm=1 for required client {ClientId}", clientId);
                }
            }
            catch (Exception ex)
            { _logger.LogDebug(ex, "[JARM-EXTRACT] Early required mode check error for client {ClientId}", clientId); }
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class ParRequestUriResolutionHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParRequestUriResolutionHandler> _logger;
    private readonly IProtocolMetrics _metrics;
    public ParRequestUriResolutionHandler(ApplicationDbContext db, ILogger<ParRequestUriResolutionHandler> logger, IProtocolMetrics metrics)
    { _db = db; _logger = logger; _metrics = metrics; }

    public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        if (context?.Request == null) return;
        var request = context.Request;

        try
        {
            var preNames = string.Join(',', request.GetParameters().Select(p => p.Key));
            _logger.LogDebug("[PAR-RESOLVE] Pre-resolve params: {Names}; request_uri={RequestUri}", preNames, request.GetParameter(OpenIddictConstants.Parameters.RequestUri));
        }
        catch { }

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
                    _logger.LogDebug("[PAR-RESOLVE] Merging {Count} stored params from PAR", dict.Count);
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
                { _logger.LogWarning(ex, "[PAR] Failed to deserialize stored parameters for {RequestUri}", requestUri); }
            }

            request.SetParameter("_par_request_uri", requestUri);
            try { context.Transaction!.Properties["mrwho.par.request_uri"] = requestUri; } catch { }

            request.SetParameter(OpenIddictConstants.Parameters.RequestUri, null);
            request.RequestUri = null;
            if (context.Transaction?.Request != null)
            {
                context.Transaction.Request.SetParameter(OpenIddictConstants.Parameters.RequestUri, null);
                context.Transaction.Request.RequestUri = null;
            }
            request.SetParameter("_par_resolved", "1");

            try
            {
                var postNames = string.Join(',', request.GetParameters().Select(p => p.Key));
                _logger.LogDebug("[PAR-RESOLVE] Post-resolve params: {Names}; request cleared={Cleared}", postNames, request.GetParameter(OpenIddictConstants.Parameters.RequestUri) is null && request.RequestUri is null);
            }
            catch { }

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

internal sealed class ParConsumptionHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly IOptions<OidcAdvancedOptions> _adv;
    private readonly ILogger<ParConsumptionHandler> _logger;
    private readonly IProtocolMetrics _metrics;
    public ParConsumptionHandler(ApplicationDbContext db, IOptions<OidcAdvancedOptions> adv, ILogger<ParConsumptionHandler> logger, IProtocolMetrics metrics)
    { _db = db; _adv = adv; _logger = logger; _metrics = metrics; }

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        if (context.Request == null) return;
        var request = context.Request;
        var requestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri)?.ToString();
        if (string.IsNullOrWhiteSpace(requestUri)) requestUri = request.GetParameter("_par_request_uri")?.ToString();
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

internal sealed class ParModeEnforcementHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
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
            if (parMode == PushedAuthorizationMode.Required)
            {
                bool resolved = request.GetParameter("_par_resolved") is not null;
                bool hasRequestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri) is not null || !string.IsNullOrEmpty(request.RequestUri);
                if (!resolved && !hasRequestUri)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "PAR required for this client");
                    _logger.LogDebug("[PAR] Rejected authorize request missing request_uri/resolution (ParMode=Required) client {ClientId}", clientId);
                }
            }
        }
        catch (Exception ex)
        { _logger.LogDebug(ex, "[PAR] Native ParMode enforcement skipped due to error for client {ClientId}", clientId); }
        return ValueTask.CompletedTask;
    }
}

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
        if (string.IsNullOrEmpty(clientId)) return ValueTask.CompletedTask;
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
                bool parResolved = request.GetParameter("_par_resolved") is not null;
                bool hasRequestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri) is not null || !string.IsNullOrEmpty(request.RequestUri);
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
        { _logger.LogDebug(ex, "[JAR] JarMode enforcement skipped due to error for client {ClientId}", clientId); }
        return ValueTask.CompletedTask;
    }
}

internal sealed class JarValidateRequestObjectHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly IJarValidationService _validator;
    private readonly ILogger<JarValidateRequestObjectHandler> _logger;
    private readonly OidcAdvancedOptions _adv;
    private readonly IJarReplayCache _replay;
    private readonly JarOptions _jarOptions;
    private readonly IProtocolMetrics _metrics;
    public JarValidateRequestObjectHandler(IJarValidationService validator, ILogger<JarValidateRequestObjectHandler> logger, IOptions<OidcAdvancedOptions> adv, IJarReplayCache replay, IOptions<JarOptions> jarOptions, IProtocolMetrics metrics)
    { _validator = validator; _logger = logger; _adv = adv.Value; _replay = replay; _jarOptions = jarOptions.Value; _metrics = metrics; }

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var req = context.Request;
        if (req == null) return;
        var raw = req.Request;
        if (string.IsNullOrEmpty(raw)) return;
        try
        {
            _logger.LogDebug("[JAR-VALIDATE] Validating inbound request object; len={Len}", raw?.Length);
            var result = await _validator.ValidateAsync(raw, req.ClientId, context.CancellationToken);
            if (!result.Success)
            {
                _metrics.IncrementJarRequest("reject", result.Algorithm ?? "unknown");
                _logger.LogWarning("[JAR-VALIDATE] Rejected request object: alg={Alg} error={Error} desc={Desc}", result.Algorithm, result.Error, result.ErrorDescription);
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
                { try { exp = DateTimeOffset.FromUnixTimeSeconds(expEpoch); } catch { }
                }
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
            req.Request = null;
            req.SetParameter(OpenIddictConstants.Parameters.Request, null);
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
            _logger.LogError(ex, "[JAR-VALIDATE] Error validating request object at validate stage");
            _metrics.IncrementJarRequest("error", "unknown");
            context.Reject(error: OpenIddictConstants.Errors.InvalidRequestObject, description: "invalid request object");
        }
    }
}

internal sealed class RedirectUriExtractHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    private readonly ILogger<RedirectUriExtractHandler> _logger;
    public RedirectUriExtractHandler(ILogger<RedirectUriExtractHandler> logger) => _logger = logger;

    public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        var req = context.Transaction?.Request ?? context.Request;
        if (req == null) return ValueTask.CompletedTask;
        try
        {
            var redirectParam = req.GetParameter(OpenIddictConstants.Parameters.RedirectUri)?.ToString();
            if (string.IsNullOrWhiteSpace(req.RedirectUri) && !string.IsNullOrWhiteSpace(redirectParam))
            {
                req.RedirectUri = redirectParam;
                if (context.Transaction?.Request != null && string.IsNullOrWhiteSpace(context.Transaction.Request.RedirectUri))
                {
                    context.Transaction.Request.RedirectUri = redirectParam;
                }
                _logger.LogDebug("[REDIRECT-EXTRACT] Applied redirect_uri from parameters at extract stage: {Redirect}", redirectParam);
            }
        }
        catch (Exception ex)
        { _logger.LogDebug(ex, "[REDIRECT-EXTRACT] Failed while applying redirect_uri at extract stage"); }
        return ValueTask.CompletedTask;
    }
}

internal sealed class RedirectUriFallbackHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    private readonly ILogger<RedirectUriFallbackHandler> _logger;
    public RedirectUriFallbackHandler(ILogger<RedirectUriFallbackHandler> logger) => _logger = logger;

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var req = context.Transaction?.Request ?? context.Request;
        if (req == null) return ValueTask.CompletedTask;
        try
        {
            var redirectParam = req.GetParameter(OpenIddictConstants.Parameters.RedirectUri)?.ToString();
            if (string.IsNullOrWhiteSpace(req.RedirectUri) && !string.IsNullOrWhiteSpace(redirectParam))
            {
                req.RedirectUri = redirectParam;
                if (context.Transaction?.Request != null && string.IsNullOrWhiteSpace(context.Transaction.Request.RedirectUri))
                {
                    context.Transaction.Request.RedirectUri = redirectParam;
                }
                _logger.LogDebug("[REDIRECT-FALLBACK] Applied redirect_uri from parameters: {Redirect}", redirectParam);
            }
            var names = string.Join(',', req.GetParameters().Select(p => p.Key));
            _logger.LogDebug("[VALIDATE] Params snapshot before core validation: [{Names}]; client_id={ClientId}; redirect_uri={Redirect}", names, req.ClientId, req.RedirectUri);
        }
        catch (Exception ex)
        { _logger.LogDebug(ex, "[REDIRECT-FALLBACK] Failed while applying/logging redirect_uri"); }
        return ValueTask.CompletedTask;
    }
}

internal sealed class AuthResponseDebugLogger : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    private readonly ILogger<AuthResponseDebugLogger> _logger;
    public AuthResponseDebugLogger(ILogger<AuthResponseDebugLogger> logger) => _logger = logger;

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        try
        {
            var req = context.Request;
            var names = req is null ? "<none>" : string.Join(',', req.GetParameters().Select(p => p.Key));
            var hasPar = req?.GetParameter("_par_resolved") is not null;
            var hasJar = req?.GetParameter("_jar_validated") is not null || !string.IsNullOrEmpty(req?.Request);
            var err = context.Response?[OpenIddictConstants.Parameters.Error]?.ToString();
            var desc = context.Response?[OpenIddictConstants.Parameters.ErrorDescription]?.ToString();
            _logger.LogWarning("[AUTH-RESP] error={Error} desc={Desc}; params=[{Names}] par={Par} jar={Jar}", err, desc, names, hasPar, hasJar);
        }
        catch (Exception ex)
        { _logger.LogDebug(ex, "[AUTH-RESP] Failed to log response details"); }
        return ValueTask.CompletedTask;
    }
}

internal sealed class MrWhoShortCircuitExtractHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        var openidRequest = context.Request;
        if (openidRequest is null) return ValueTask.CompletedTask;
        if (openidRequest.GetParameter("_jar_validated") is not null)
        {
            // Ensure 'request' not processed again
            openidRequest.Request = null;
            openidRequest.SetParameter(OpenIddictConstants.Parameters.Request, null);
            if (context.Transaction?.Request != null)
            {
                context.Transaction.Request.Request = null;
                context.Transaction.Request.SetParameter(OpenIddictConstants.Parameters.Request, null);
            }
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class MrWhoShortCircuitValidateHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var req = context.Request;
        if (req is null) return ValueTask.CompletedTask;
        if (req.GetParameter("_jar_validated") is not null)
        {
            req.Request = null;
            req.SetParameter(OpenIddictConstants.Parameters.Request, null);
            if (context.Transaction?.Request != null)
            {
                context.Transaction.Request.Request = null;
                context.Transaction.Request.SetParameter(OpenIddictConstants.Parameters.Request, null);
            }
        }
        return ValueTask.CompletedTask;
    }
}

public static class JarJarmServerEventHandlers
{
    public static OpenIddictServerHandlerDescriptor ConfigurationHandlerDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseScopedHandler<DiscoveryAugmentationHandler>()
            .SetOrder(0)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ParRequestUriResolutionDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<ParRequestUriResolutionHandler>()
            .SetOrder(int.MinValue)
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
            .SetOrder(int.MinValue + 2)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor JarEarlyExtractAndValidateDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<JarEarlyExtractAndValidateHandler>()
            .SetOrder(int.MinValue + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    // Run redirect_uri fallback first in validate stage so core validators see the property set.
    public static OpenIddictServerHandlerDescriptor RedirectUriFallbackDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<RedirectUriFallbackHandler>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    // Run conflict/limits after redirect fallback
    public static OpenIddictServerHandlerDescriptor RequestConflictAndLimitValidationDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<RequestConflictAndLimitValidationHandler>()
            .SetOrder(int.MinValue + 1)
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
            .SetOrder(int.MinValue + 2)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor AuthorizationResponseDebugLoggerDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<AuthResponseDebugLogger>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ExtractRedirectUriFallbackDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<RedirectUriExtractHandler>()
            .SetOrder(int.MinValue + 2)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ShortCircuitExtractDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<MrWhoShortCircuitExtractHandler>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ShortCircuitValidateDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<MrWhoShortCircuitValidateHandler>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();
}
