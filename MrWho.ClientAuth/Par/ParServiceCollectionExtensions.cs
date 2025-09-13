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
}
