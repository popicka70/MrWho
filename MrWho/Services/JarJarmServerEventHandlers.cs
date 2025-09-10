using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json; // for fallback JSON element
using OpenIddict.Abstractions;

namespace MrWho.Services;

public class JarOptions
{
    public const string SectionName = "Jar";
    public int MaxRequestObjectBytes { get; set; } = 4096;
    public bool RequireJti { get; set; } = true;
    public TimeSpan JtiCacheWindow { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan MaxExp { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
}

public interface IJarReplayCache { bool TryAdd(string key, DateTimeOffset expiresUtc); }
public sealed class InMemoryJarReplayCache : IJarReplayCache
{
    private readonly IMemoryCache _cache; public InMemoryJarReplayCache(IMemoryCache cache) => _cache = cache;
    public bool TryAdd(string key, DateTimeOffset expiresUtc)
    { if (_cache.TryGetValue(key, out _)) return false; var ttl = expiresUtc - DateTimeOffset.UtcNow; if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromSeconds(1); _cache.Set(key, 1, ttl); return true; }
}

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
            // Flags
            resp[OpenIddictConstants.Metadata.RequestParameterSupported] = true; // request= supported
            resp[OpenIddictConstants.Metadata.RequestUriParameterSupported] = false; // request_uri disabled
            resp["authorization_response_iss_parameter_supported"] = true; // JARM related

            // Attempt to augment existing response_modes_supported if present
            var current = resp[OpenIddictConstants.Metadata.ResponseModesSupported];
            var added = false;
            if (current is not null)
            {
                var asString = current.ToString();
                if (!string.IsNullOrWhiteSpace(asString) && asString.Contains("query") && !asString.Contains("jwt"))
                {
                    // crude string based rebuild (OpenIddictParameter array construction APIs differ across versions)
                    using var doc = JsonDocument.Parse(asString.StartsWith("[") ? asString : "[\"query\",\"fragment\",\"form_post\"]");
                    var list = doc.RootElement.EnumerateArray().Select(e => e.GetString()!).ToList();
                    if (!list.Contains("jwt")) list.Add("jwt");
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

            // request_object_signing_alg_values_supported
            using var algsDoc = JsonDocument.Parse("[\"RS256\",\"HS256\"]");
            resp[OpenIddictConstants.Metadata.RequestObjectSigningAlgValuesSupported] = algsDoc.RootElement.Clone();

            _logger.LogInformation("DiscoveryAugmentationHandler applied (jwt mode advertised: {Added})", true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "DiscoveryAugmentationHandler failed applying JAR/JARM metadata");
        }
        return ValueTask.CompletedTask;
    }
}

internal sealed class NoopAuthorizationResponseHandler : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{ public ValueTask HandleAsync(ApplyAuthorizationResponseContext context) => ValueTask.CompletedTask; }

public static class JarJarmServerEventHandlers
{
    public static OpenIddictServerHandlerDescriptor ConfigurationHandlerDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyConfigurationResponseContext>()
            .UseScopedHandler<DiscoveryAugmentationHandler>()
            .SetOrder(0) // run early so later handlers can still see jwt mode
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor ApplyAuthorizationResponseDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<NoopAuthorizationResponseHandler>()
            .SetOrder(int.MaxValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();
}
