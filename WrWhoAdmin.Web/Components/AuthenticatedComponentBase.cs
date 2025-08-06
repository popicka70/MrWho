using Microsoft.AspNetCore.Components;
using MrWhoAdmin.Web.Services;

namespace MrWhoAdmin.Web.Components;

/// <summary>
/// Base component that handles authentication automatically
/// </summary>
public abstract class AuthenticatedComponentBase : ComponentBase
{
    [Inject] protected IBlazorAuthService BlazorAuthService { get; set; } = default!;
    [Inject] protected ILogger<AuthenticatedComponentBase> Logger { get; set; } = default!;

    protected bool IsLoading { get; set; } = true;
    protected bool IsAuthenticated { get; set; } = false;
    protected string? AuthErrorMessage { get; set; }
    private bool _hasRendered = false;

    protected override async Task OnInitializedAsync()
    {
        // During prerendering, we'll assume authentication is OK
        // and perform the real check after the component becomes interactive
        
        if (!_hasRendered)
        {
            // Set initial state for prerendering
            IsLoading = true;
            IsAuthenticated = true; // Assume authenticated during prerendering
            
            // Check for authentication errors in URL (this is safe during prerendering)
            if (BlazorAuthService.HasAuthenticationError())
            {
                AuthErrorMessage = BlazorAuthService.GetAuthenticationErrorMessage();
                Logger.LogWarning("Authentication error detected in URL: {ErrorMessage}", AuthErrorMessage);
                IsAuthenticated = false;
            }
        }
        
        await base.OnInitializedAsync();
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            _hasRendered = true;
            // Now we're in an interactive context, perform the real authentication check
            await CheckAuthenticationAsync();
        }
        
        await base.OnAfterRenderAsync(firstRender);
    }

    /// <summary>
    /// Checks authentication status and handles re-authentication if needed
    /// </summary>
    protected virtual async Task CheckAuthenticationAsync()
    {
        try
        {
            IsLoading = true;
            StateHasChanged();

            Logger.LogDebug("Checking authentication status (interactive context)");
            
            // Re-check for authentication errors in URL
            if (BlazorAuthService.HasAuthenticationError())
            {
                AuthErrorMessage = BlazorAuthService.GetAuthenticationErrorMessage();
                Logger.LogWarning("Authentication error detected: {ErrorMessage}", AuthErrorMessage);
                IsAuthenticated = false;
                return;
            }

            // Ensure user is authenticated (this will now work in interactive context)
            IsAuthenticated = await BlazorAuthService.EnsureAuthenticatedAsync();
            
            if (IsAuthenticated)
            {
                Logger.LogDebug("Authentication check successful");
                // Clear any previous error messages
                AuthErrorMessage = null;
                // Call the virtual method for derived classes
                await OnAuthenticatedAsync();
            }
            else
            {
                Logger.LogWarning("Authentication check failed, re-authentication may have been triggered");
                // Don't set error message here as TriggerReauthenticationAsync should handle the redirect
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during authentication check");
            AuthErrorMessage = "Authentication check failed. Please try refreshing the page.";
            IsAuthenticated = false;
        }
        finally
        {
            IsLoading = false;
            StateHasChanged();
        }
    }

    /// <summary>
    /// Manually trigger re-authentication (safe to call after first render)
    /// </summary>
    protected async Task TriggerReauthenticationAsync()
    {
        try
        {
            if (!_hasRendered)
            {
                Logger.LogWarning("TriggerReauthenticationAsync called before first render, deferring");
                // If called before first render, just set error state
                AuthErrorMessage = "Authentication required. Please refresh the page to log in.";
                IsAuthenticated = false;
                StateHasChanged();
                return;
            }

            Logger.LogInformation("Manually triggering re-authentication");
            await BlazorAuthService.TriggerReauthenticationAsync();
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error triggering re-authentication");
            AuthErrorMessage = "Failed to trigger re-authentication. Please try refreshing the page.";
            StateHasChanged();
        }
    }

    /// <summary>
    /// Clear authentication error message
    /// </summary>
    protected void ClearAuthError()
    {
        AuthErrorMessage = null;
        StateHasChanged();
    }

    /// <summary>
    /// Override this method to perform actions after successful authentication
    /// </summary>
    protected virtual Task OnAuthenticatedAsync()
    {
        return Task.CompletedTask;
    }

    /// <summary>
    /// Helper method to render authentication status
    /// </summary>
    protected RenderFragment RenderAuthenticationStatus() => builder =>
    {
        if (IsLoading)
        {
            builder.OpenElement(0, "div");
            builder.AddAttribute(1, "class", "d-flex justify-content-center p-4");
            builder.OpenElement(2, "div");
            builder.AddAttribute(3, "class", "spinner-border text-primary");
            builder.AddAttribute(4, "role", "status");
            builder.OpenElement(5, "span");
            builder.AddAttribute(6, "class", "visually-hidden");
            builder.AddContent(7, "Loading...");
            builder.CloseElement();
            builder.CloseElement();
            builder.CloseElement();
        }
        else if (!string.IsNullOrEmpty(AuthErrorMessage))
        {
            builder.OpenElement(8, "div");
            builder.AddAttribute(9, "class", "alert alert-danger");
            builder.AddContent(10, AuthErrorMessage);
            
            // Only add the login button if we've rendered (interactive context)
            if (_hasRendered)
            {
                builder.OpenElement(11, "button");
                builder.AddAttribute(12, "type", "button");
                builder.AddAttribute(13, "class", "btn btn-primary ms-2");
                builder.AddAttribute(14, "onclick", EventCallback.Factory.Create(this, TriggerReauthenticationAsync));
                builder.AddContent(15, "Login Again");
                builder.CloseElement();
            }
            else
            {
                builder.OpenElement(16, "small");
                builder.AddAttribute(17, "class", "text-muted d-block mt-2");
                builder.AddContent(18, "Please refresh the page to log in.");
                builder.CloseElement();
            }
            
            builder.CloseElement();
        }
        else if (!IsAuthenticated)
        {
            builder.OpenElement(19, "div");
            builder.AddAttribute(20, "class", "alert alert-warning");
            builder.AddContent(21, "You are not authenticated. Redirecting to login...");
            builder.CloseElement();
        }
    };
}