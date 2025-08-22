using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Extension methods for registering machine-to-machine (client_credentials) and user-forwarded HttpClients.
/// </summary>
public static class MrWhoClientAuthM2MExtensions
{
    private static IServiceCollection AddMrWhoM2MCore(this IServiceCollection services, Action<MrWhoClientCredentialsOptions> configure)
    {
        services.Configure(configure);

        // Token acquisition client
        services.AddHttpClient(MrWhoClientAuthDefaults.TokenHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp =>
            {
                var opt = sp.GetRequiredService<IOptions<MrWhoClientCredentialsOptions>>().Value;
                var handler = new HttpClientHandler();
                if (opt.AcceptAnyServerCertificate)
                {
                    handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }
                return handler;
            });

        services.AddSingleton<IMrWhoClientCredentialsTokenProvider, MrWhoClientCredentialsTokenProvider>();
        services.AddTransient<MrWhoClientCredentialsHandler>();
        return services;
    }

    /// <summary>
    /// Registers a named HttpClient that automatically acquires and attaches a client_credentials token.
    /// </summary>
    public static IHttpClientBuilder AddMrWhoClientCredentialsApi(this IServiceCollection services,
        string name,
        Uri baseAddress,
        Action<MrWhoClientCredentialsOptions> configure)
    {
        services.AddMrWhoM2MCore(configure);
        return services.AddHttpClient(name, c => c.BaseAddress = baseAddress)
                       .AddHttpMessageHandler<MrWhoClientCredentialsHandler>();
    }

    /// <summary>
    /// Registers a typed HttpClient that uses client_credentials tokens.
    /// </summary>
    public static IHttpClientBuilder AddMrWhoClientCredentialsApi<TClient>(this IServiceCollection services,
        Uri baseAddress,
        Action<MrWhoClientCredentialsOptions> configure) where TClient : class
    {
        services.AddMrWhoM2MCore(configure);
        return services.AddHttpClient<TClient>(c => c.BaseAddress = baseAddress)
                       .AddHttpMessageHandler<MrWhoClientCredentialsHandler>();
    }

    /// <summary>
    /// Registers a named HttpClient that forwards the current user's access token (delegated user -> API).
    /// </summary>
    public static IHttpClientBuilder AddMrWhoUserAccessTokenApi(this IServiceCollection services,
        string name, Uri baseAddress)
    {
        services.AddHttpContextAccessor();
        services.AddTransient<MrWhoUserAccessTokenHandler>();
        return services.AddHttpClient(name, c => c.BaseAddress = baseAddress)
                       .AddHttpMessageHandler<MrWhoUserAccessTokenHandler>();
    }

    /// <summary>
    /// Registers a typed HttpClient variant that forwards the current user's access token.
    /// </summary>
    public static IHttpClientBuilder AddMrWhoUserAccessTokenApi<TClient>(this IServiceCollection services,
        Uri baseAddress) where TClient : class
    {
        services.AddHttpContextAccessor();
        services.AddTransient<MrWhoUserAccessTokenHandler>();
        return services.AddHttpClient<TClient>(c => c.BaseAddress = baseAddress)
                       .AddHttpMessageHandler<MrWhoUserAccessTokenHandler>();
    }
}
