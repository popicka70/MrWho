using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Middleware;

namespace MrWhoAdmin.Web.Extensions;

/// <summary>
/// Extension methods for configuring the WebApplication middleware pipeline
/// </summary>
public static class WebApplicationExtensions
{
    /// <summary>
    /// Configures the middleware pipeline in the correct order
    /// </summary>
    public static WebApplication ConfigureMiddlewarePipeline(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error", createScopeForErrors: true);
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        
        // Add token refresh middleware after authentication but before other middleware
        app.UseMiddleware<TokenRefreshMiddleware>();
        
        app.UseAntiforgery();
        app.UseOutputCache();
        app.MapStaticAssets();

        return app;
    }

    /// <summary>
    /// Configures authentication endpoints for login and logout
    /// </summary>
    public static WebApplication ConfigureAuthenticationEndpoints(this WebApplication app)
    {
        const string adminCookieScheme = "AdminCookies"; // Match the scheme from AddAuthenticationServices
        
        // Login endpoint - trigger OIDC challenge
        app.MapGet("/login", async (HttpContext context, string? returnUrl = null) =>
        {
            // Ensure we have a valid return URL
            var redirectUri = string.IsNullOrEmpty(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative) 
                ? "/" 
                : returnUrl;

            var properties = new AuthenticationProperties
            {
                RedirectUri = redirectUri
            };

            // Clear any existing authentication state before challenging
            await context.SignOutAsync(adminCookieScheme);
            
            // Trigger OpenIdConnect challenge
            await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
        });

        // Logout endpoint
        app.MapGet("/logout", async (HttpContext context, string? returnUrl = null) =>
        {
            var redirectUri = string.IsNullOrEmpty(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative) 
                ? "/" 
                : returnUrl;

            var properties = new AuthenticationProperties
            {
                RedirectUri = redirectUri
            };

            // Sign out from both cookie and OIDC schemes
            await context.SignOutAsync(adminCookieScheme);
            await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
        });

        // Add explicit handling for OIDC callback paths to prevent 404s
        app.MapGet("/signin-oidc", () => "OIDC callback endpoint - this should not be called directly");
        app.MapGet("/signout-callback-oidc", () => "OIDC signout callback endpoint - this should not be called directly");

        // Debug endpoint to clear authentication state (development only)
        if (app.Environment.IsDevelopment())
        {
            app.MapGet("/debug/clear-auth", async (HttpContext context) =>
            {
                await context.SignOutAsync(adminCookieScheme);
                await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                
                // Clear all cookies
                foreach (var cookie in context.Request.Cookies.Keys)
                {
                    context.Response.Cookies.Delete(cookie);
                }
                
                return Results.Redirect("/");
            });
        }

        return app;
    }

    /// <summary>
    /// Configures Blazor routing and component registration
    /// </summary>
    public static WebApplication ConfigureBlazorRouting(this WebApplication app)
    {
        // Configure Blazor components properly
        app.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode()
            .AddAdditionalAssemblies(typeof(Radzen.Blazor.RadzenButton).Assembly);

        return app;
    }
}