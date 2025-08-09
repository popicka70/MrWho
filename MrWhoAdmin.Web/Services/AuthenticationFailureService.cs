using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service to handle authentication failures and automatic logout in Blazor components
/// </summary>
public interface IAuthenticationFailureService
{
    /// <summary>
    /// Handles authentication failure (403, 401) and redirects to appropriate error page
    /// </summary>
    Task HandleAuthenticationFailureAsync(int statusCode, string? requestPath = null, string? error = null);
    
    /// <summary>
    /// Handles API authentication failures
    /// </summary>
    Task HandleApiAuthenticationFailureAsync(HttpResponseMessage response, string? requestPath = null);
    
    /// <summary>
    /// Checks if a response indicates authentication failure
    /// </summary>
    bool IsAuthenticationFailure(HttpResponseMessage response);
}

public class AuthenticationFailureService : IAuthenticationFailureService
{
    private readonly NavigationManager _navigationManager;
    private readonly IJSRuntime _jsRuntime;
    private readonly ILogger<AuthenticationFailureService> _logger;

    public AuthenticationFailureService(
        NavigationManager navigationManager,
        IJSRuntime jsRuntime,
        ILogger<AuthenticationFailureService> logger)
    {
        _navigationManager = navigationManager;
        _jsRuntime = jsRuntime;
        _logger = logger;
    }

    public Task HandleAuthenticationFailureAsync(int statusCode, string? requestPath = null, string? error = null)
    {
        _logger.LogWarning("Authentication failure detected. StatusCode: {StatusCode}, Path: {Path}, Error: {Error}",
            statusCode, requestPath, error);

        try
        {
            var currentPath = requestPath ?? _navigationManager.ToBaseRelativePath(_navigationManager.Uri);
            
            // Build error URL with details
            var errorUrl = "/auth/error?" +
                          $"error={Uri.EscapeDataString(error ?? "authentication_failed")}&" +
                          $"error_description={Uri.EscapeDataString(GetErrorDescription(statusCode))}&" +
                          $"status_code={statusCode}&" +
                          $"original_path={Uri.EscapeDataString(currentPath)}";

            _logger.LogInformation("Redirecting to authentication error page: {ErrorUrl}", errorUrl);
            
            _navigationManager.NavigateTo(errorUrl, forceLoad: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling authentication failure");
            
            // Fallback
            _navigationManager.NavigateTo("/auth/error", forceLoad: true);
        }

        return Task.CompletedTask;
    }

    public Task HandleApiAuthenticationFailureAsync(HttpResponseMessage response, string? requestPath = null)
    {
        var statusCode = (int)response.StatusCode;
        var error = response.ReasonPhrase ?? "api_authentication_failed";
        HandleAuthenticationFailureAsync(statusCode, requestPath, error);
        return Task.CompletedTask;
    }

    public bool IsAuthenticationFailure(HttpResponseMessage response)
    {
        return response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
               response.StatusCode == System.Net.HttpStatusCode.Forbidden;
    }

    private string GetErrorDescription(int statusCode)
    {
        return statusCode switch
        {
            401 => "Authentication required - please log in",
            403 => "Access denied - your session may have expired or been revoked",
            _ => "Authentication or authorization failed"
        };
    }
}