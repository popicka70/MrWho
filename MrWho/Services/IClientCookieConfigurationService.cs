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
    
    /// <summary>
    /// Checks if a client has static cookie configuration
    /// </summary>
    bool HasStaticConfiguration(string clientId);
    
    /// <summary>
    /// Checks if a client should use dynamic cookie management
    /// </summary>
    bool UsesDynamicCookies(string clientId);
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