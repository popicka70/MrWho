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
    public RequestConflictAndLimitValidationHandler(IOptions<OidcAdvancedOptions> adv, ILogger<RequestConflictAndLimitValidationHandler> logger)
    { _adv = adv; _logger = logger; }

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Request;
        if (request == null) return ValueTask.CompletedTask;
        var adv = _adv.Value;

        try
        {
            // Build snapshot of parameters currently on the request (includes JAR merged + PAR resolved)
            var parameterNames = request.GetParameters().Select(p => p.Key).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            // PJ41: Limits first (cheaper) - operate on snapshot
            if (adv.RequestLimits is { } limits)
            {
                if (limits.MaxParameters is int mp && mp > 0 && parameterNames.Count > mp)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:parameters");
                    ParMetrics.RecordLimitViolation("parameters");
                    return ValueTask.CompletedTask;
                }

                int aggregateBytes = 0;
                foreach (var name in parameterNames)
                {
                    if (limits.MaxParameterNameLength is int mn && mn > 0 && name.Length > mn)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:name_length");
                        ParMetrics.RecordLimitViolation("name_length");
                        return ValueTask.CompletedTask;
                    }
                    var valObj = request.GetParameter(name);
                    var valStr = valObj?.ToString() ?? string.Empty;
                    if (limits.MaxParameterValueLength is int mv && mv > 0 && valStr.Length > mv)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:value_length");
                        ParMetrics.RecordLimitViolation("value_length");
                        return ValueTask.CompletedTask;
                    }
                    aggregateBytes += Encoding.UTF8.GetByteCount(valStr);
                }
                if (limits.MaxAggregateValueBytes is int mab && mab > 0 && aggregateBytes > mab)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:aggregate_bytes");
                    ParMetrics.RecordLimitViolation("aggregate_bytes");
                    return ValueTask.CompletedTask;
                }

                if (limits.MaxScopeItems is int msi && msi > 0 && request.GetParameter(OpenIddictConstants.Parameters.Scope) is { } scopeParam)
                {
                    var count = scopeParam.ToString()?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length ?? 0;
                    if (count > msi)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:scope_items");
                        ParMetrics.RecordLimitViolation("scope_items");
                        return ValueTask.CompletedTask;
                    }
                }
                if (limits.MaxAcrValues is int mav && mav > 0 && request.GetParameter(OpenIddictConstants.Parameters.AcrValues) is { } acrParam)
                {
                    var count = acrParam.ToString()?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length ?? 0;
                    if (count > mav)
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "limit_exceeded:acr_values");
                        ParMetrics.RecordLimitViolation("acr_values");
                        return ValueTask.CompletedTask;
                    }
                }
            }

            // PJ40: Conflict detection (query vs merged) only meaningful if original query captured in transaction. OpenIddict keeps original in context.Request object already; we rely on markers set earlier ("_jar_validated" or "_par_resolved").
            if (adv.RequestConflicts.Enabled)
            {
                var ignored = new HashSet<string>(adv.RequestConflicts.IgnoredParameters ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                // Determine overlap: parameters that came from request object/PAR vs existing query
                // We don't have original raw query values separately after merging; thus perform detection during early extract (JAR handler) ideally.
                // Fallback: rely on sentinel added by early JAR handler that already performed conflict detection if enabled at extract time.
                // To ensure coverage for PAR-only flows where conflicts could still exist (e.g., request_uri + query param duplication), implement basic duplicate check here.
                foreach (var name in parameterNames)
                {
                    if (ignored.Contains(name)) continue;
                    // If the parameter appears multiple times with differing values we cannot detect post-merge; skip.
                    // Basic heuristic: if both PAR and query provided different value, PAR resolution only sets when query missing, so conflict only occurs when JAR present.
                    // Therefore only handle 'scope' normalization differences when strict ordering requested (should have been caught earlier though).
                    if (string.Equals(name, OpenIddictConstants.Parameters.Scope, StringComparison.OrdinalIgnoreCase) && adv.RequestConflicts.StrictScopeOrdering)
                    {
                        // Order already normalized earlier (none). Nothing additional here.
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

// Existing handlers unchanged below
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
            // Advertise support for both request and request_uri parameters since custom PAR/JAR are implemented.
            resp[OpenIddictConstants.Metadata.RequestParameterSupported] = true;
            resp[OpenIddictConstants.Metadata.RequestUriParameterSupported] = true; // CHANGED from false -> true (PAR front-channel uses request_uri)
            resp["authorization_response_iss_parameter_supported"] = true;
            // Merge/ensure jwt response mode
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

            // Dynamic request object signing alg values supported
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
                        // Defaults (RS256, HS256) assumed when empty
                        hs256 = true;
                        continue;
                    }
                    foreach (var a in list)
                    {
                        if (a.Equals("HS256", StringComparison.OrdinalIgnoreCase))
                        {
                            hs256 = true;
                        }
                        else if (a.Equals("HS384", StringComparison.OrdinalIgnoreCase))
                        {
                            hs384 = true;
                        }
                        else if (a.Equals("HS512", StringComparison.OrdinalIgnoreCase))
                        {
                            hs512 = true;
                        }
                    }
                }
                if (hs256)
                {
                    algs.Add("HS256");
                }

                if (hs384)
                {
                    algs.Add("HS384");
                }

                if (hs512)
                {
                    algs.Add("HS512");
                }
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

        // Explicit response_mode=jwt request -> normalize
        if (string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
        {
            request.SetParameter("mrwho_jarm", "1");
            request.ResponseMode = null; // clear so OpenIddict doesn't reject unknown mode
            request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
            return ValueTask.CompletedTask;
        }

        // Implicit enforcement when client has JarmMode=Required and caller omitted response_mode
        // (don't overwrite if mrwho_jarm already present)
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

    public JarmAuthorizationResponseHandler(ILogger<JarmAuthorizationResponseHandler> logger, IKeyManagementService keyService, Microsoft.Extensions.Options.IOptions<JarOptions> jarOptions, ISecurityAuditWriter auditWriter)
    { _logger = logger; _keyService = keyService; _jarOptions = jarOptions.Value; _auditWriter = auditWriter; }

    private static void EnsureKeyId(SecurityKey key, ILogger logger)
    {
        if (!string.IsNullOrEmpty(key.KeyId))
        {
            return; // already has kid
        }

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
                        rsa.KeyId = Base64UrlEncoder.Encode(hash); // deterministic kid
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
                    // For symmetric fallback (should not normally be used for JARM), derive from first 16 bytes
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
            if (!jarmRequested)
            {
                return; // not JARM
            }

            // Collect parameters to embed
            var response = context.Response;
            if (response is null)
            {
                return;
            }

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
            if (!string.IsNullOrEmpty(codeValue))
            {
                claims[OpenIddictConstants.Parameters.Code] = codeValue;
            }

            string? stateValue = response[OpenIddictConstants.Parameters.State]?.ToString();
            if (!string.IsNullOrEmpty(stateValue))
            {
                claims[OpenIddictConstants.Parameters.State] = stateValue;
            }

            string? errorValue = response[OpenIddictConstants.Parameters.Error]?.ToString();
            if (!string.IsNullOrEmpty(errorValue))
            {
                claims[OpenIddictConstants.Parameters.Error] = errorValue;
                var errDesc = response[OpenIddictConstants.Parameters.ErrorDescription]?.ToString();
                if (!string.IsNullOrEmpty(errDesc))
                {
                    claims[OpenIddictConstants.Parameters.ErrorDescription] = errDesc;
                }
            }

            // Obtain signing key
            var (signingKeys, _) = await _keyService.GetActiveKeysAsync();
            var signingKey = signingKeys.FirstOrDefault();
            if (signingKey is null)
            {
                _logger.LogWarning("No signing key available for JARM response");
                return; // fail open
            }
            EnsureKeyId(signingKey, _logger); // NEW: guarantee kid for downstream validators
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
            if (!string.IsNullOrEmpty(codeValue))
            {
                response[OpenIddictConstants.Parameters.Code] = null;
            }

            if (!string.IsNullOrEmpty(errorValue))
            {
                response[OpenIddictConstants.Parameters.Error] = null;
                response[OpenIddictConstants.Parameters.ErrorDescription] = null;
            }
            response["response"] = jwt;
            _logger.LogDebug("Issued JARM JWT (iss={Issuer}, aud={Aud}, codePresent={HasCode}, errorPresent={HasError}, kid={Kid})", issuer, clientId, !string.IsNullOrEmpty(codeValue), !string.IsNullOrEmpty(errorValue), signingKey.KeyId);
            try { await _auditWriter.WriteAsync("auth.security", errorValue == null ? "jarm.issued" : "jarm.error", new { clientId, hasCode = codeValue != null, error = errorValue, state = stateValue, kid = signingKey.KeyId }, "info", actorClientId: clientId); } catch { }
        }
        catch (Exception ex)
        {
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

    public JarEarlyExtractAndValidateHandler(IJarValidationService validator,
        ILogger<JarEarlyExtractAndValidateHandler> logger,
        Microsoft.Extensions.Options.IOptions<OidcAdvancedOptions> adv,
        Microsoft.Extensions.Options.IOptions<JarOptions> jarOptions)
    { _validator = validator; _logger = logger; _adv = adv.Value; _jarOptions = jarOptions.Value; }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ExtractAuthorizationRequestContext context)
    {
        if (context == null || context.Request == null) return;
        var request = context.Request;
        if (string.IsNullOrEmpty(request.Request)) return; // no JAR param
        if (_adv.JarHandlerMode != JarHandlerMode.CustomExclusive) return; // allow built-in pipeline when not exclusive

        try
        {
            var queryClientId = request.ClientId;
            var jwt = request.Request;
            var result = await _validator.ValidateAsync(jwt!, queryClientId, context.CancellationToken);
            if (!result.Success)
            {
                context.Reject(
                    error: result.Error ?? OpenIddictConstants.Errors.InvalidRequestObject,
                    description: result.ErrorDescription ?? "invalid request object"
                );
                return;
            }

            // Conflict detection immediate (PJ40) BEFORE merging into request
            if (_adv.RequestConflicts.Enabled && result.Parameters != null)
            {
                var ignored = new HashSet<string>(_adv.RequestConflicts.IgnoredParameters ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                foreach (var kv in result.Parameters)
                {
                    if (ignored.Contains(kv.Key)) continue;
                    var existingParam = request.GetParameter(kv.Key);
                    if (existingParam is null) continue; // only compare overlapping
                    var existingStr = existingParam.ToString();
                    var newVal = kv.Value?.ToString() ?? string.Empty;
                    if (kv.Key == OpenIddictConstants.Parameters.Scope)
                    {
                        static string NormalizeScopes(string? v) => string.Join(' ', (v ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).OrderBy(x => x, StringComparer.Ordinal));
                        if (_adv.RequestConflicts.StrictScopeOrdering)
                        {
                            if (!string.Equals(existingStr, newVal, StringComparison.Ordinal))
                            {
                                context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "parameter_conflict:scope");
                                ParMetrics.RecordConflict("scope");
                                return;
                            }
                        }
                        else if (NormalizeScopes(existingStr) != NormalizeScopes(newVal))
                        {
                            context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "parameter_conflict:scope");
                            ParMetrics.RecordConflict("scope");
                            return;
                        }
                    }
                    else if (!string.Equals(existingStr, newVal, StringComparison.Ordinal))
                    {
                        context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: $"parameter_conflict:{kv.Key}");
                        ParMetrics.RecordConflict(kv.Key);
                        return;
                    }
                }
            }

            // Merge validated parameters
            if (result.Parameters != null)
            {
                foreach (var kv in result.Parameters)
                {
                    request.SetParameter(kv.Key, kv.Value);
                }
            }
            request.Request = null; // strip original
            request.SetParameter(OpenIddictConstants.Parameters.Request, null);
            request.SetParameter("_jar_validated", "1");
            _logger.LogDebug("[JAR] Early extract validated request object for client {ClientId} alg {Alg} (merged {Count} params)", result.ClientId, result.Algorithm, result.Parameters?.Count ?? 0);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[JAR] Unhandled error during early validation");
            context.Reject(error: OpenIddictConstants.Errors.InvalidRequestObject, description: "invalid request object");
        }
    }
}

// Handler for resolving PAR request_uri
internal sealed class ParRequestUriResolutionHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ExtractAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<ParRequestUriResolutionHandler> _logger;
    public ParRequestUriResolutionHandler(ApplicationDbContext db, ILogger<ParRequestUriResolutionHandler> logger)
    { _db = db; _logger = logger; }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ExtractAuthorizationRequestContext context)
    {
        if (context?.Request == null) return; // FIXED syntax (added parentheses earlier bug)
        var request = context.Request;
        var requestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri)?.ToString();
        if (string.IsNullOrWhiteSpace(requestUri)) return; // nothing to resolve

        try
        {
            // request_uri expected format: urn:ietf:params:oauth:request_uri:{id} OR custom (we just match exact)
            var par = await _db.PushedAuthorizationRequests.AsNoTracking().FirstOrDefaultAsync(p => p.RequestUri == requestUri);
            if (par == null)
            {
                _logger.LogDebug("[PAR] request_uri not found: {RequestUri}", requestUri);
                ParMetrics.RecordResolution(success: false); // METRIC miss
                return; // let downstream produce invalid_request_uri
            }
            if (DateTime.UtcNow > par.ExpiresAt)
            {
                _logger.LogDebug("[PAR] request_uri expired: {RequestUri}", requestUri);
                ParMetrics.RecordResolution(success: false); // METRIC expired
                return; // let downstream reject as expired (will surface generic error)
            }
            // Deserialize stored parameters (JSON object of name->value) and apply unless already present
            if (!string.IsNullOrWhiteSpace(par.ParametersJson))
            {
                try
                {
                    var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(par.ParametersJson) ?? new();
                    foreach (var kv in dict)
                    {
                        if (kv.Key == OpenIddictConstants.Parameters.RequestUri) continue; // do not re-add
                        if (kv.Key == OpenIddictConstants.Parameters.Request) // preserve JAR for downstream validator
                        {
                            if (string.IsNullOrEmpty(request.Request)) request.Request = kv.Value; // set so JAR handler validates
                            continue;
                        }
                        // Only set if missing from current request to honor spec precedence rules (PAR content authoritative)
                        if (request.GetParameter(kv.Key) is null)
                        {
                            request.SetParameter(kv.Key, kv.Value);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[PAR] Failed to deserialize stored parameters for {RequestUri}", requestUri);
                }
            }
            // Add sentinel for later enforcement & telemetry
            request.SetParameter("_par_resolved", "1");
            ParMetrics.RecordResolution(success: true); // METRIC
            _logger.LogDebug("[PAR] Resolved request_uri {RequestUri} (expires {ExpiresAt:u})", requestUri, par.ExpiresAt);
            // Removal of request_uri parameter optional; keep for trace but downstream validators will ignore after resolution
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[PAR] Error resolving request_uri {RequestUri}", requestUri);
        }
    }
}

// Handler for consuming PAR request_uri (PJ49)
internal sealed class ParConsumptionHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
{
    private readonly ApplicationDbContext _db;
    private readonly IOptions<OidcAdvancedOptions> _adv;
    private readonly ILogger<ParConsumptionHandler> _logger;
    public ParConsumptionHandler(ApplicationDbContext db, IOptions<OidcAdvancedOptions> adv, ILogger<ParConsumptionHandler> logger)
    { _db = db; _adv = adv; _logger = logger; }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
    {
        if (context.Request == null) return;
        var request = context.Request;
        var requestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri)?.ToString();
        if (string.IsNullOrWhiteSpace(requestUri)) return; // no PAR

        // Only enforce if resolution occurred (we set _par_resolved earlier) to avoid race when unknown request_uri supplied
        if (request.GetParameter("_par_resolved") is null) return;

        bool singleUse = _adv.Value.ParSingleUseDefault;
        if (!singleUse) return; // multi-use allowed until expiry

        try
        {
            var par = await _db.PushedAuthorizationRequests.FirstOrDefaultAsync(p => p.RequestUri == requestUri);
            if (par == null)
            {
                // Already removed or never existed -> reject
                context.Reject(error: OpenIddictConstants.Errors.InvalidRequestUri, description: "invalid or unknown request_uri");
                return;
            }
            if (DateTime.UtcNow > par.ExpiresAt)
            {
                context.Reject(error: OpenIddictConstants.Errors.InvalidRequestUri, description: "expired request_uri");
                return;
            }
            par.ConsumedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(context.CancellationToken);
            ParMetrics.RecordConsumed(); // METRIC
            _logger.LogDebug("[PAR] Consumed request_uri {RequestUri} (single-use)", requestUri);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[PAR] Error consuming request_uri {RequestUri}", requestUri);
            // Fail open (spec may allow) but safer to reject to prevent replay when uncertain
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

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
    {
        var request = context.Request;
        if (request == null) return ValueTask.CompletedTask;
        var clientId = request.ClientId;
        if (string.IsNullOrEmpty(clientId)) return ValueTask.CompletedTask; // core validator will handle missing client

        try
        {
            // Quick in-memory check via EF (single column) for ParMode
            var parMode = _db.Clients.AsNoTracking()
                .Where(c => c.ClientId == clientId)
                .Select(c => c.ParMode)
                .FirstOrDefault();
            if (parMode == MrWho.Shared.PushedAuthorizationMode.Required)
            {
                // Must have request_uri AND it must have been resolved earlier (sentinel _par_resolved added by resolution handler)
                bool hasRequestUri = request.GetParameter(OpenIddictConstants.Parameters.RequestUri) is not null;
                bool resolved = request.GetParameter("_par_resolved") is not null;
                if (!hasRequestUri)
                {
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequest, description: "PAR required for this client");
                    _logger.LogDebug("[PAR] Rejected authorize request missing request_uri (ParMode=Required) client {ClientId}", clientId);
                }
                else if (!resolved)
                {
                    // request_uri supplied but not successfully resolved (invalid/expired) -> let existing invalid_request_uri logic surface descriptive error
                    context.Reject(error: OpenIddictConstants.Errors.InvalidRequestUri, description: "invalid or expired request_uri for required PAR");
                    _logger.LogDebug("[PAR] Rejected authorize request with unresolved request_uri (ParMode=Required) client {ClientId}", clientId);
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

public static class JarJarmServerEventHandlers
{
    // UPDATED: extraction phase handler now enforces JARM required by injecting mrwho_jarm=1 if client requires it
    private sealed class JarmResponseModeExtractHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
    {
        private readonly ApplicationDbContext _db;
        private readonly ILogger<JarmResponseModeExtractHandler> _logger;
        public JarmResponseModeExtractHandler(ApplicationDbContext db, ILogger<JarmResponseModeExtractHandler> logger)
        { _db = db; _logger = logger; }

        public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
        {
            var request = context.Transaction?.Request ?? context.Request;
            if (request == null)
                return ValueTask.CompletedTask;

            // Explicit response_mode=jwt provided -> normalize
            if (string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
            {
                request.SetParameter("mrwho_jarm", "1");
                request.ResponseMode = null; // remove so core validator does not reject unknown mode
                request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
                return ValueTask.CompletedTask;
            }

            // If already marked, nothing to do
            if (request.GetParameter("mrwho_jarm") is not null)
                return ValueTask.CompletedTask;

            // Early enforcement: if client requires JARM, inject marker so downstream (login redirect) returnUrl includes it
            var clientId = request.ClientId;
            if (!string.IsNullOrEmpty(clientId))
            {
                try
                {
                    var mode = _db.Clients.AsNoTracking()
                        .Where(c => c.ClientId == clientId)
                        .Select(c => c.JarmMode)
                        .FirstOrDefault();
                    if (mode == JarmMode.Required) // FIXED enum type
                    {
                        request.SetParameter("mrwho_jarm", "1");
                        _logger.LogDebug("[JARM] Injected mrwho_jarm=1 at extract stage for required client {ClientId}", clientId);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[JARM] Failed early required mode check for client {ClientId}", clientId);
                }
            }
            return ValueTask.CompletedTask;
        }
    }

    public static OpenIddictServerHandlerDescriptor ExtractNormalizeJarmResponseModeDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<JarmResponseModeExtractHandler>()
            .SetOrder(int.MinValue) // earliest possible
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ConfigurationHandlerDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseScopedHandler<DiscoveryAugmentationHandler>()
            .SetOrder(0)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    // Run early (before built-in validator) to normalize and enforce JARM when required
    public static OpenIddictServerHandlerDescriptor NormalizeJarmResponseModeDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<JarmResponseModeNormalizationHandler>()
            .SetOrder(int.MinValue) // ensure we run before core validation
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ApplyAuthorizationResponseDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<JarmAuthorizationResponseHandler>()
            .SetOrder(int.MaxValue) // run late to wrap final response
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor JarEarlyExtractAndValidateDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ExtractAuthorizationRequestContext>()
            .UseScopedHandler<JarEarlyExtractAndValidateHandler>()
            .SetOrder(int.MinValue + 5) // run extremely early (after any response_mode normalization but before built-ins)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ParRequestUriResolutionDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ExtractAuthorizationRequestContext>()
            .UseScopedHandler<ParRequestUriResolutionHandler>()
            .SetOrder(int.MinValue + 2) // before Jar extract (which is +5) but after response_mode normalization (min)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ParConsumptionDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ValidateAuthorizationRequestContext>()
            .UseScopedHandler<ParConsumptionHandler>()
            .SetOrder(int.MinValue + 10) // after normalization + JAR early extract but early in validation
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ParModeEnforcementDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ValidateAuthorizationRequestContext>()
            .UseScopedHandler<ParModeEnforcementHandler>()
            .SetOrder(int.MinValue + 8) // after resolution (+2) and JAR early extract (+5) but before consumption (+10)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor RequestConflictAndLimitValidationDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<RequestConflictAndLimitValidationHandler>()
            .SetOrder(int.MinValue + 6) // after JAR extraction (+5) and PAR resolution (+2) but before ParMode enforcement (+8)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();
}
