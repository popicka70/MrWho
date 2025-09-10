using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json; // for JSON array construction
using OpenIddict.Abstractions;
using Microsoft.IdentityModel.Tokens; // signing
using Microsoft.IdentityModel.JsonWebTokens;

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
    public DiscoveryAugmentationHandler(ILogger<DiscoveryAugmentationHandler> logger) => _logger = logger;

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
            using var algsDoc = JsonDocument.Parse("[\"RS256\",\"HS256\"]");
            resp[OpenIddictConstants.Metadata.RequestObjectSigningAlgValuesSupported] = algsDoc.RootElement.Clone();
            _logger.LogDebug("Discovery metadata augmented with jwt response mode.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed augmenting discovery metadata");
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

    public JarmAuthorizationResponseHandler(ILogger<JarmAuthorizationResponseHandler> logger, IKeyManagementService keyService, Microsoft.Extensions.Options.IOptions<JarOptions> jarOptions)
    { _logger = logger; _keyService = keyService; _jarOptions = jarOptions.Value; }

    public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        try
        {
            if (!string.Equals(context.Request?.ResponseMode, "jwt", StringComparison.OrdinalIgnoreCase))
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
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create JARM response JWT");
        }
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

    public static OpenIddictServerHandlerDescriptor ApplyAuthorizationResponseDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<JarmAuthorizationResponseHandler>()
            .SetOrder(int.MaxValue) // run late to wrap final response
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();
}
