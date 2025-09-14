using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Services;
using MrWho.Shared.Authentication; // unify naming
using OpenIddict.Abstractions;

namespace MrWho.Services;

/// <summary>
/// Implementation of client-specific cookie configuration service
/// </summary>
public class ClientCookieConfigurationService : IClientCookieConfigurationService
{
    private readonly ILogger<ClientCookieConfigurationService> _logger;
    private readonly IOidcClientService _oidcClientService;
    private readonly IOptions<MrWhoOptions> _options;
    private readonly ApplicationDbContext _db;

    public ClientCookieConfigurationService(
        ILogger<ClientCookieConfigurationService> logger,
        IOidcClientService oidcClientService,
        IOptions<MrWhoOptions> options,
        ApplicationDbContext db)
    {
        _logger = logger;
        _oidcClientService = oidcClientService;
        _options = options;
        _db = db;
    }


    public string GetCookieSchemeForClient(string clientId)
    {
        var mode = _options.Value.CookieSeparationMode;
        switch (mode)
        {
            case CookieSeparationMode.None:
                // Use default Identity application scheme
                return IdentityConstants.ApplicationScheme;

            case CookieSeparationMode.ByRealm:
                var realmKey = GetRealmKeyForClient(clientId);
                return CookieSchemeNaming.BuildRealmScheme(realmKey);

            case CookieSeparationMode.ByClient:
            default:
                // Dynamic per-client scheme
                var dynamicSchemeName = CookieSchemeNaming.BuildClientScheme(clientId);
                _logger.LogDebug("Using dynamic authentication scheme for client {ClientId}: {SchemeName}", clientId, dynamicSchemeName);
                return dynamicSchemeName;
        }
    }

    public string GetCookieNameForClient(string clientId)
    {
        var mode = _options.Value.CookieSeparationMode;
        switch (mode)
        {
            case CookieSeparationMode.None:
                // Default identity cookie name
                return CookieSchemeNaming.DefaultCookieName;

            case CookieSeparationMode.ByRealm:
                var realmKey = GetRealmKeyForClient(clientId);
                return CookieSchemeNaming.BuildRealmCookie(realmKey);

            case CookieSeparationMode.ByClient:
            default:
                var dynamicCookieName = CookieSchemeNaming.BuildClientCookie(clientId);
                _logger.LogDebug("Using dynamic cookie name for client {ClientId}: {CookieName}", clientId, dynamicCookieName);
                return dynamicCookieName;
        }
    }

    /// <summary>
    /// Checks if a client should use dynamic cookies
    /// </summary>
    public bool UsesDynamicCookies(string clientId)
    {
        var mode = _options.Value.CookieSeparationMode;
        if (mode == CookieSeparationMode.None)
        {
            return false; // default scheme/cookie
        }
        if (mode == CookieSeparationMode.ByRealm)
        {
            return true; // dynamic per-realm scheme
        }
        return true;
    }

    public async Task<string?> GetClientIdFromRequestAsync(HttpContext context)
    {
        await Task.CompletedTask; // Ensure async completion
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
        var dict = new Dictionary<string, ClientCookieConfiguration>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var mode = _options.Value.CookieSeparationMode;

            // Default Identity cookie when not separating
            if (mode == CookieSeparationMode.None)
            {
                dict["default"] = new ClientCookieConfiguration
                {
                    ClientId = "default",
                    SchemeName = IdentityConstants.ApplicationScheme,
                    CookieName = CookieSchemeNaming.DefaultCookieName
                };
            }

            // Load enabled clients from the database (sync wait is fine on ASP.NET Core)
            var clients = _oidcClientService.GetEnabledClientsAsync().GetAwaiter().GetResult();
            foreach (var client in clients)
            {
                var id = client.ClientId;
                if (string.IsNullOrWhiteSpace(id)) {
                    continue;
                }

                var scheme = GetCookieSchemeForClient(id);
                var cookie = GetCookieNameForClient(id);
                dict[id] = new ClientCookieConfiguration
                {
                    ClientId = id,
                    SchemeName = scheme,
                    CookieName = cookie
                };
            }

            _logger.LogDebug("Enumerated {Count} client cookie configurations", dict.Count);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enumerate client cookie configurations");
        }

        return dict;
    }

    private string GetRealmKeyForClient(string clientId)
    {
        try
        {
            // Look up the client's realm name; fallback to Default
            var realmName = _db.Clients
                .Include(c => c.Realm)
                .Where(c => c.ClientId == clientId && c.IsEnabled)
                .Select(c => c.Realm.Name)
                .FirstOrDefault();

            realmName ??= "Default";
            return CookieSchemeNaming.Sanitize(realmName);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to resolve realm for client {ClientId}", clientId);
            return "Default";
        }
    }
}