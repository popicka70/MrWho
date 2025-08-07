using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service to handle authentication-related operations in Blazor components
/// </summary>
public class BlazorAuthService : IBlazorAuthService
{
    private readonly IJSRuntime _jsRuntime;
    private readonly ILogger<BlazorAuthService> _logger;
    private readonly NavigationManager _navigationManager;

    public BlazorAuthService(
        IJSRuntime jsRuntime, 
        ILogger<BlazorAuthService> logger,
        NavigationManager navigationManager)
    {
        _jsRuntime = jsRuntime;
        _logger = logger;
        _navigationManager = navigationManager;
    }

    /// <summary>
    /// Redirects to the authentication check endpoint which will handle re-authentication if needed
    /// </summary>
    /// <param name="returnUrl">URL to return to after authentication</param>
    public async Task TriggerReauthenticationAsync(string? returnUrl = null)
    {
        try
        {
            var currentUrl = returnUrl ?? _navigationManager.Uri;
            var encodedReturnUrl = Uri.EscapeDataString(currentUrl);
            var checkAuthUrl = $"/auth/check-and-reauth?returnUrl={encodedReturnUrl}";
            
            _logger.LogInformation("Triggering re-authentication via redirect to {CheckAuthUrl}", checkAuthUrl);
            
            // Check if we can use JavaScript (not during prerendering)
            if (_jsRuntime is IJSInProcessRuntime)
            {
                // We're in an interactive context, use JavaScript navigation
                await _jsRuntime.InvokeVoidAsync("window.location.href", checkAuthUrl);
            }
            else
            {
                // We're in a prerendering context, use server-side navigation
                // This will work during static rendering
                _navigationManager.NavigateTo(checkAuthUrl, forceLoad: true);
            }
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("JavaScript interop calls cannot be issued"))
        {
            _logger.LogWarning("JavaScript interop not available (prerendering), using server-side navigation");
            
            // Fallback to server-side navigation
            var currentUrl = returnUrl ?? _navigationManager.Uri;
            var encodedReturnUrl = Uri.EscapeDataString(currentUrl);
            var checkAuthUrl = $"/auth/check-and-reauth?returnUrl={encodedReturnUrl}";
            
            _navigationManager.NavigateTo(checkAuthUrl, forceLoad: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error triggering re-authentication");
            
            // Last resort fallback - simple navigation
            try
            {
                _navigationManager.NavigateTo("/login", forceLoad: true);
            }
            catch (Exception fallbackEx)
            {
                _logger.LogError(fallbackEx, "Fallback navigation also failed");
                throw; // Re-throw so the calling component can handle it
            }
        }
    }

    /// <summary>
    /// Checks if the user needs re-authentication and handles it
    /// </summary>
    /// <returns>True if authentication is valid, false if re-authentication was triggered</returns>
    public async Task<bool> EnsureAuthenticatedAsync()
    {
        try
        {
            // For now, we'll use a simpler approach that doesn't require HTTP calls during prerendering
            // The actual authentication check will be handled by the middleware and AuthenticatedComponentBase
            
            _logger.LogDebug("EnsureAuthenticatedAsync called - deferring to component lifecycle");
            
            // During prerendering, we can't make HTTP calls reliably
            // Return true and let the component handle authentication checks after rendering
            if (!IsInteractiveContext())
            {
                _logger.LogDebug("Prerendering context detected, deferring authentication check");
                return true; // Let the component handle this after interactive rendering starts
            }
            
            // In interactive context, we can perform the authentication check
            return await PerformAuthenticationCheckAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking authentication status");
            
            // If we can't check authentication status, assume not authenticated
            // and trigger re-authentication
            await TriggerReauthenticationAsync();
            return false;
        }
    }

    /// <summary>
    /// Shows a user-friendly message about authentication issues
    /// </summary>
    /// <param name="message">Custom message to display</param>
    public async Task ShowAuthErrorAsync(string? message = null)
    {
        try
        {
            var errorMessage = message ?? "Your session has expired. Please log in again.";
            
            // Only use JavaScript if we're in an interactive context
            if (IsInteractiveContext())
            {
                await _jsRuntime.InvokeVoidAsync("alert", errorMessage);
            }
            else
            {
                // During prerendering, just log the message
                _logger.LogWarning("Authentication error (prerendering): {ErrorMessage}", errorMessage);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error showing authentication error message");
        }
    }

    /// <summary>
    /// Checks if the current URL has authentication error parameters
    /// </summary>
    /// <returns>True if there are authentication errors in the URL</returns>
    public bool HasAuthenticationError()
    {
        try
        {
            var uri = new Uri(_navigationManager.Uri);
            var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
            
            return query["authError"] == "true" || 
                   query["refreshError"] == "true" ||
                   query["error"] != null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking for authentication errors in URL");
            return false;
        }
    }

    /// <summary>
    /// Gets authentication error details from URL parameters
    /// </summary>
    /// <returns>Error message if present</returns>
    public string? GetAuthenticationErrorMessage()
    {
        try
        {
            var uri = new Uri(_navigationManager.Uri);
            var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
            
            if (query["authError"] == "true")
            {
                return "Authentication failed. Please try logging in again.";
            }
            
            if (query["refreshError"] == "true")
            {
                return "Token refresh failed. Please log in again.";
            }
            
            var error = query["error"];
            if (!string.IsNullOrEmpty(error))
            {
                return $"Authentication error: {error}";
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting authentication error message");
            return "Authentication error occurred.";
        }
    }

    /// <summary>
    /// Checks if we're in an interactive context (not prerendering)
    /// </summary>
    private bool IsInteractiveContext()
    {
        try
        {
            // During prerendering, JSRuntime will be a different type
            return _jsRuntime is IJSInProcessRuntime;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Performs the actual authentication check with HTTP calls
    /// </summary>
    private async Task<bool> PerformAuthenticationCheckAsync()
    {
        try
        {
            // Make a call to check authentication status
            using var httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri(_navigationManager.BaseUri);
            httpClient.Timeout = TimeSpan.FromSeconds(5); // Short timeout
            
            var response = await httpClient.GetAsync("/auth/status");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var authStatus = System.Text.Json.JsonSerializer.Deserialize<AuthStatusResponse>(content, new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                
                if (authStatus?.Authenticated == true && authStatus.NeedsRefresh != true)
                {
                    return true; // Authentication is valid
                }
                
                if (authStatus?.Authenticated == true && authStatus.NeedsRefresh == true)
                {
                    _logger.LogInformation("Token needs refresh, triggering re-authentication");
                    await TriggerReauthenticationAsync();
                    return false;
                }
            }
            
            // Not authenticated or status check failed
            _logger.LogWarning("Authentication status check failed or user not authenticated");
            await TriggerReauthenticationAsync();
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error performing authentication check");
            return false; // Don't trigger re-auth on network errors during interactive check
        }
    }

    private class AuthStatusResponse
    {
        public bool Authenticated { get; set; }
        public bool? NeedsRefresh { get; set; }
        public string? UserName { get; set; }
        public string? Error { get; set; }
    }
}