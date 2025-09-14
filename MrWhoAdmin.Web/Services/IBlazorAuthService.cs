namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service to handle authentication-related operations in Blazor components
/// </summary>
public interface IBlazorAuthService
{
    /// <summary>
    /// Redirects to the authentication check endpoint which will handle re-authentication if needed
    /// </summary>
    /// <param name="returnUrl">URL to return to after authentication</param>
    Task TriggerReauthenticationAsync(string? returnUrl = null);

    /// <summary>
    /// Checks if the user needs re-authentication and handles it
    /// </summary>
    /// <returns>True if authentication is valid, false if re-authentication was triggered</returns>
    Task<bool> EnsureAuthenticatedAsync();

    /// <summary>
    /// Shows a user-friendly message about authentication issues
    /// </summary>
    /// <param name="message">Custom message to display</param>
    Task ShowAuthErrorAsync(string? message = null);

    /// <summary>
    /// Checks if the current URL has authentication error parameters
    /// </summary>
    /// <returns>True if there are authentication errors in the URL</returns>
    bool HasAuthenticationError();

    /// <summary>
    /// Gets authentication error details from URL parameters
    /// </summary>
    /// <returns>Error message if present</returns>
    string? GetAuthenticationErrorMessage();
}
