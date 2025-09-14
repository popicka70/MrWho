using Microsoft.AspNetCore.Components;
using MrWhoAdmin.Web.Services;

namespace MrWhoAdmin.Web.Components;

/// <summary>
/// Base component that handles authentication automatically with proper disposal and error handling
/// </summary>
public abstract class AuthenticatedComponentBase : ComponentBase, IDisposable
{
    [Inject] protected IBlazorAuthService BlazorAuthService { get; set; } = default!;
    [Inject] protected ILogger<AuthenticatedComponentBase> Logger { get; set; } = default!;

    protected bool IsLoading { get; set; } = true;
    protected bool IsAuthenticated { get; set; } = false;
    protected string? AuthErrorMessage { get; set; }
    private bool _hasRendered = false;
    private bool _disposed = false;

    protected override async Task OnInitializedAsync()
    {
        if (_disposed) {
            return;
        }

        // During prerendering, we'll assume authentication is OK
        // and perform the real check after the component becomes interactive

        if (!_hasRendered)
        {
            // Set initial state for prerendering
            IsLoading = true;
            IsAuthenticated = true; // Assume authenticated during prerendering

            // Check for authentication errors in URL (this is safe during prerendering)
            try
            {
                if (BlazorAuthService.HasAuthenticationError())
                {
                    AuthErrorMessage = BlazorAuthService.GetAuthenticationErrorMessage();
                    Logger.LogWarning("Authentication error detected in URL: {ErrorMessage}", AuthErrorMessage);
                    IsAuthenticated = false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error checking for authentication errors during initialization");
            }
        }

        await base.OnInitializedAsync();
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (_disposed) {
            return;
        }

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
        if (_disposed) {
            return;
        }

        try
        {
            IsLoading = true;
            if (!_disposed)
            {
                StateHasChanged();
            }

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
            if (!_disposed)
            {
                StateHasChanged();
            }
        }
    }

    /// <summary>
    /// Manually trigger re-authentication (safe to call after first render)
    /// </summary>
    protected async Task TriggerReauthenticationAsync()
    {
        if (_disposed) {
            return;
        }

        try
        {
            if (!_hasRendered)
            {
                Logger.LogWarning("TriggerReauthenticationAsync called before first render, deferring");
                // If called before first render, just set error state
                AuthErrorMessage = "Authentication required. Please refresh the page to log in.";
                IsAuthenticated = false;
                if (!_disposed)
                {
                    StateHasChanged();
                }
                return;
            }

            Logger.LogInformation("Manually triggering re-authentication");
            await BlazorAuthService.TriggerReauthenticationAsync();
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error triggering re-authentication");
            AuthErrorMessage = "Failed to trigger re-authentication. Please try refreshing the page.";
            if (!_disposed)
            {
                StateHasChanged();
            }
        }
    }

    /// <summary>
    /// Clear authentication error message
    /// </summary>
    protected void ClearAuthError()
    {
        if (_disposed) {
            return;
        }

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
        if (_disposed) {
            return;
        }

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
            builder.OpenElement(0, "div");
            builder.AddAttribute(1, "class", "alert alert-danger");
            builder.AddContent(2, AuthErrorMessage);
            builder.OpenElement(3, "button");
            builder.AddAttribute(4, "type", "button");
            builder.AddAttribute(5, "class", "btn btn-primary mt-2");
            builder.AddAttribute(6, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create(this, TriggerReauthenticationAsync));
            builder.AddContent(7, "Try Login Again");
            builder.CloseElement();
            builder.CloseElement();
        }
        else if (!IsAuthenticated)
        {
            builder.OpenElement(0, "div");
            builder.AddAttribute(1, "class", "alert alert-warning");
            builder.AddContent(2, "Authentication required. Please log in to continue.");
            builder.OpenElement(3, "button");
            builder.AddAttribute(4, "type", "button");
            builder.AddAttribute(5, "class", "btn btn-primary mt-2");
            builder.AddAttribute(6, "onclick", Microsoft.AspNetCore.Components.EventCallback.Factory.Create(this, TriggerReauthenticationAsync));
            builder.AddContent(7, "Login");
            builder.CloseElement();
            builder.CloseElement();
        }
    };

    public virtual void Dispose()
    {
        _disposed = true;
    }
}