using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;

namespace MrWho.Services;

/// <summary>
/// Ensures OpenIddict client registrations used for interactive flows have absolute RedirectUri/PostLogoutRedirectUri set.
/// This fixes "A redirection URI must be specified" errors when the registration doesn't explicitly set them.
/// </summary>
public sealed class OpenIddictClientOptionsPostConfigurator : IPostConfigureOptions<OpenIddictClientOptions>
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<OpenIddictClientOptionsPostConfigurator> _logger;

    public OpenIddictClientOptionsPostConfigurator(
        IConfiguration configuration,
        ILogger<OpenIddictClientOptionsPostConfigurator> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public void PostConfigure(string? name, OpenIddictClientOptions options)
    {
        var baseUrl = (_configuration["PublicUrl"] ?? _configuration["OpenIddict:Issuer"] ?? "https://localhost:7113").TrimEnd('/');
        var callback = new Uri($"{baseUrl}/connect/external/callback", UriKind.Absolute);
        var signoutCallback = new Uri($"{baseUrl}/connect/external/signout-callback", UriKind.Absolute);

        if (options.Registrations.Count == 0)
        {
            _logger.LogDebug("OpenIddictClientOptions has no registrations in PostConfigure.");
            return;
        }

        foreach (var reg in options.Registrations)
        {
            if (reg.RedirectUri is null)
            {
                reg.RedirectUri = callback;
                _logger.LogInformation("Set missing RedirectUri for OpenIddict client registration {RegistrationIdOrIssuer} to {RedirectUri}",
                    reg.RegistrationId ?? reg.Issuer?.AbsoluteUri ?? "<unknown>", callback);
            }

            if (reg.PostLogoutRedirectUri is null)
            {
                reg.PostLogoutRedirectUri = signoutCallback;
                _logger.LogInformation("Set missing PostLogoutRedirectUri for OpenIddict client registration {RegistrationIdOrIssuer} to {PostLogoutRedirectUri}",
                    reg.RegistrationId ?? reg.Issuer?.AbsoluteUri ?? "<unknown>", signoutCallback);
            }
        }
    }
}
