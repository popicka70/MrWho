using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MrWho.ClientAuth.Jar;

namespace MrWho.ClientAuth.Par;

public static class ParServiceCollectionExtensions
{
    /// <summary>
    /// Registers the PAR client service with required HttpClient. Caller must configure ParClientOptions.
    /// If a JAR signer (IJarRequestObjectSigner) is also registered, PAR service can auto-produce request objects.
    /// </summary>
    public static IServiceCollection AddMrWhoParClient(this IServiceCollection services, Action<ParClientOptions> configure)
    {
        var opts = new ParClientOptions { ParEndpoint = new Uri("https://localhost:7113/connect/par") }; // placeholder defaults
        configure(opts);
        services.AddSingleton(opts);
        services.AddHttpClient<IPushedAuthorizationService, PushedAuthorizationService>();
        return services;
    }

    /// <summary>
    /// Convenience overload: register PAR using an Authority (base URL). Optionally customize via configure.
    /// </summary>
    public static IServiceCollection AddMrWhoParClient(this IServiceCollection services, string authority, Action<ParClientOptions>? configure = null)
    {
        var baseUrl = authority?.TrimEnd('/') ?? "https://localhost:7113";
        var opts = new ParClientOptions
        {
            ParEndpoint = new Uri(baseUrl + "/connect/par"),
            AuthorizeEndpoint = new Uri(baseUrl + "/connect/authorize")
        };
        configure?.Invoke(opts);
        services.AddSingleton(opts);
        services.AddHttpClient<IPushedAuthorizationService, PushedAuthorizationService>();
        return services;
    }

    /// <summary>
    /// Convenience overload: bind options from configuration section keys: Authority, Par:TimeoutSeconds, Par:AutoPushQueryLengthThreshold, Par:FallbackWhenDisabled, Par:AutoJar.
    /// </summary>
    public static IServiceCollection AddMrWhoParClient(this IServiceCollection services, IConfiguration config)
    {
        var authority = config["Authority"] ?? config["Authentication:Authority"] ?? "https://localhost:7113";
        return services.AddMrWhoParClient(authority, opts =>
        {
            if (int.TryParse(config["Par:TimeoutSeconds"], out var ts) && ts > 0)
            {
                opts.Timeout = TimeSpan.FromSeconds(ts);
            }
            if (int.TryParse(config["Par:AutoPushQueryLengthThreshold"], out var thr))
            {
                opts.AutoPushQueryLengthThreshold = thr;
            }
            if (bool.TryParse(config["Par:FallbackWhenDisabled"], out var fb))
            {
                opts.FallbackWhenDisabled = fb;
            }
            if (bool.TryParse(config["Par:AutoJar"], out var aj))
            {
                opts.AutoJar = aj;
            }
        });
    }
}
