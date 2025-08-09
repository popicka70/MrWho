using Microsoft.AspNetCore.Authentication.Cookies;
using MrWho.Services;
using OpenIddict.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;

namespace MrWho.Services;

/// <summary>
/// Implementation of client-specific cookie configuration service
/// </summary>
public class ClientCookieConfigurationService : IClientCookieConfigurationService
{
    private readonly ILogger<ClientCookieConfigurationService> _logger;
    private readonly IOidcClientService _oidcClientService;

    // Static mapping of known clients to their cookie configurations
    private static readonly Dictionary<string, ClientCookieConfiguration> ClientCookieConfigurations = new()
    {
        { 
            "mrwho_admin_web", 
            new ClientCookieConfiguration
            {
                ClientId = "mrwho_admin_web",
                SchemeName = "Identity.Application.mrwho_admin_web",
                CookieName = ".MrWho.Admin"
            }
        },
        { 
            "mrwho_demo1", 
            new ClientCookieConfiguration
            {
                ClientId = "mrwho_demo1",
                SchemeName = "Identity.Application.mrwho_demo1",
                CookieName = ".MrWho.Demo1"
            }
        },
        { 
            "postman_client", 
            new ClientCookieConfiguration
            {
                ClientId = "postman_client",
                SchemeName = "Identity.Application.postman_client",
                CookieName = ".MrWho.API"
            }
        }
    };

    public ClientCookieConfigurationService(
        ILogger<ClientCookieConfigurationService> logger,
        IOidcClientService oidcClientService)
    {
        _logger = logger;
        _oidcClientService = oidcClientService;
    }

    public string GetCookieSchemeForClient(string clientId)
    {
        if (ClientCookieConfigurations.TryGetValue(clientId, out var config))
        {
            return config.SchemeName;
        }

        // For true dynamic configuration, all clients without static config use the default scheme
        // The cookie differentiation happens at the cookie NAME level, not the scheme level
        _logger.LogDebug("Client {ClientId} using default authentication scheme with dynamic cookie management", clientId);
        return "Identity.Application";
    }

    public string GetCookieNameForClient(string clientId)
    {
        if (ClientCookieConfigurations.TryGetValue(clientId, out var config))
        {
            return config.CookieName;
        }

        // Dynamic cookie naming - each client gets its own cookie name
        // This allows session isolation without requiring separate authentication schemes
        var dynamicCookieName = $".MrWho.{clientId}";
        _logger.LogDebug("Client {ClientId} using dynamic cookie name: {CookieName}", clientId, dynamicCookieName);
        return dynamicCookieName;
    }

    /// <summary>
    /// Checks if a client has static cookie configuration
    /// </summary>
    public bool HasStaticConfiguration(string clientId)
    {
        var hasStatic = ClientCookieConfigurations.ContainsKey(clientId);
        _logger.LogDebug("?? Static Configuration Check: Client {ClientId} has static config: {HasStatic}", 
            clientId, hasStatic);
        return hasStatic;
    }

    /// <summary>
    /// Checks if a client should use dynamic cookie management
    /// </summary>
    public bool UsesDynamicCookies(string clientId)
    {
        return !HasStaticConfiguration(clientId);
    }

    public async Task<string?> GetClientIdFromRequestAsync(HttpContext context)
    {
        // Method 1: Try to get client_id from query parameters (authorization endpoint)
        if (context.Request.Query.TryGetValue("client_id", out var clientIdQuery))
        {
            var clientId = clientIdQuery.FirstOrDefault();
            if (!string.IsNullOrEmpty(clientId))
            {
                _logger.LogDebug("Found client_id in query parameters: {ClientId}", clientId);
                return clientId;
            }
        }

        // Method 2: Try to get client_id from OpenIddict request context
        try
        {
            var oidcRequest = context.GetOpenIddictServerRequest();
            if (!string.IsNullOrEmpty(oidcRequest?.ClientId))
            {
                _logger.LogDebug("Found client_id in OpenIddict request: {ClientId}", oidcRequest.ClientId);
                return oidcRequest.ClientId;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Could not get OpenIddict request: {Error}", ex.Message);
        }

        // Method 3: Try to get from form data (token endpoint)
        if (context.Request.HasFormContentType && context.Request.Form.TryGetValue("client_id", out var formClientId))
        {
            var clientId = formClientId.FirstOrDefault();
            if (!string.IsNullOrEmpty(clientId))
            {
                _logger.LogDebug("Found client_id in form data: {ClientId}", clientId);
                return clientId;
            }
        }

        // Method 4: Try to determine from existing authentication cookies
        foreach (var (clientId, config) in ClientCookieConfigurations)
        {
            if (context.Request.Cookies.ContainsKey(config.CookieName))
            {
                try
                {
                    var authResult = await context.AuthenticateAsync(config.SchemeName);
                    if (authResult.Succeeded && authResult.Principal?.Identity?.IsAuthenticated == true)
                    {
                        _logger.LogDebug("Found active session for client {ClientId} via cookie {CookieName}", 
                            clientId, config.CookieName);
                        return clientId;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("Could not authenticate with scheme {Scheme}: {Error}", config.SchemeName, ex.Message);
                }
            }
        }

        // Method 5: Check if this is a callback and get from state parameter or stored session
        if (context.Request.Path.StartsWithSegments("/signin-oidc") || 
            context.Request.Path.StartsWithSegments("/connect/authorize"))
        {
            // For callbacks, we might need to store the client_id in session during the initial challenge
            if (context.Session.IsAvailable && context.Session.TryGetValue("oidc_client_id", out var sessionClientId))
            {
                var clientId = System.Text.Encoding.UTF8.GetString(sessionClientId);
                _logger.LogDebug("Found client_id in session: {ClientId}", clientId);
                return clientId;
            }
        }

        _logger.LogDebug("Could not determine client_id from request");
        return null;
    }

    public IDictionary<string, ClientCookieConfiguration> GetAllClientConfigurations()
    {
        return new Dictionary<string, ClientCookieConfiguration>(ClientCookieConfigurations);
    }
}