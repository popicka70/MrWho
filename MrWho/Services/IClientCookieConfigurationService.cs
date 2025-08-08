using Microsoft.AspNetCore.Authentication.Cookies;

namespace MrWho.Services;

/// <summary>
/// Service for managing client-specific cookie configurations
/// </summary>
public interface IClientCookieConfigurationService
{
    /// <summary>
    /// Gets the authentication scheme name for a specific client
    /// </summary>
    string GetCookieSchemeForClient(string clientId);
    
    /// <summary>
    /// Gets the cookie name for a specific client
    /// </summary>
    string GetCookieNameForClient(string clientId);
    
    /// <summary>
    /// Attempts to determine the client ID from the current HTTP request
    /// </summary>
    Task<string?> GetClientIdFromRequestAsync(HttpContext context);
    
    /// <summary>
    /// Gets all configured client cookie schemes
    /// </summary>
    IDictionary<string, ClientCookieConfiguration> GetAllClientConfigurations();
}

/// <summary>
/// Configuration for client-specific cookies
/// </summary>
public class ClientCookieConfiguration
{
    public string ClientId { get; set; } = string.Empty;
    public string SchemeName { get; set; } = string.Empty;
    public string CookieName { get; set; } = string.Empty;
    public Action<CookieAuthenticationOptions>? ConfigureOptions { get; set; }
}