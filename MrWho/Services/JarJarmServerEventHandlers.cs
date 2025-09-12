using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json; // for JSON array construction
using OpenIddict.Abstractions;
using Microsoft.IdentityModel.Tokens; // signing
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.EntityFrameworkCore; // added for context queries
using MrWho.Options; // for symmetric policy options
using MrWho.Data; // for ApplicationDbContext
using MrWho.Shared; // for JarMode enum

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
}

public interface IJarReplayCache { bool TryAdd(string key, DateTimeOffset expiresUtc); }
public sealed class InMemoryJarReplayCache : IJarReplayCache
{
    private readonly IMemoryCache _cache; public InMemoryJarReplayCache(IMemoryCache cache) => _cache = cache;
    public bool TryAdd(string key, DateTimeOffset expiresUtc)
    { if (_cache.TryGetValue(key, out _)) return false; var ttl = expiresUtc - DateTimeOffset.UtcNow; if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromSeconds(1); _cache.Set(key, 1, ttl); return true; }
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
        if (resp is null) return ValueTask.CompletedTask;
        try
        {
            resp[OpenIddictConstants.Metadata.RequestParameterSupported] = true;
            resp[OpenIddictConstants.Metadata.RequestUriParameterSupported] = false;
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
            _logger.LogDebug("Discovery metadata augmented (request_object_signing_alg_values_supported={Algs})", string.Join(',', algs));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed augmenting discovery metadata");
        }
        return ValueTask.CompletedTask;
    }
}

// Normalization handler: allow response_mode=jwt even if core validation doesn't know it.
// We preserve the intent via a custom parameter and clear ResponseMode so default processing continues.
internal sealed class JarmResponseModeNormalizationHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        var request = context.Transaction?.Request ?? context.Request;
        if (request != null && string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
        {
            request.SetParameter("mrwho_jarm", "1");
            request.ResponseMode = null;
            request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
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
                return; // fail open
            }
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
            _logger.LogDebug("Issued JARM JWT (iss={Issuer}, aud={Aud}, codePresent={HasCode}, errorPresent={HasError})", issuer, clientId, !string.IsNullOrEmpty(codeValue), !string.IsNullOrEmpty(errorValue));
            try { await _auditWriter.WriteAsync("auth.security", errorValue==null?"jarm.issued":"jarm.error", new { clientId, hasCode = codeValue!=null, error = errorValue, state = stateValue }, "info", actorClientId: clientId); } catch { }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create JARM response JWT");
            try { await _auditWriter.WriteAsync("auth.security", "jarm.failure", new { ex = ex.Message }, "error"); } catch { }
        }
    }
}

public static class JarJarmServerEventHandlers
{
    // NEW: extraction phase handler to normalize response_mode before validation
    private sealed class JarmResponseModeExtractHandler : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
    {
        public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
        {
            var request = context.Transaction?.Request ?? context.Request;
            if (request != null && string.Equals(request.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
            {
                request.SetParameter("mrwho_jarm", "1");
                request.ResponseMode = null;
                request.SetParameter(OpenIddictConstants.Parameters.ResponseMode, null);
            }
            return ValueTask.CompletedTask;
        }
    }

    public static OpenIddictServerHandlerDescriptor ExtractNormalizeJarmResponseModeDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<JarmResponseModeExtractHandler>()
            .SetOrder(int.MinValue) // earliest possible to rewrite before built-in extraction rejects
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ConfigurationHandlerDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseScopedHandler<DiscoveryAugmentationHandler>()
            .SetOrder(0)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    // Run early (before built-in validator) to normalize response_mode=jwt
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
}
