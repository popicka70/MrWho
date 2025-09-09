using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Middleware;
using MrWhoAdmin.Web.Services;
using Radzen;

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
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error", createScopeForErrors: true);
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        // Allow disabling HTTPS redirection for containerized scenarios without TLS termination
        var disableHttpsRedirect = app.Configuration.GetValue<bool>("DISABLE_HTTPS_REDIRECT");
        if (!disableHttpsRedirect)
        {
            app.UseHttpsRedirection();
        }
        else
        {
            var logger = app.Services.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("HTTPS redirection is disabled via DISABLE_HTTPS_REDIRECT configuration. Running over HTTP.");
        }

        app.UseStaticFiles();
        app.UseRouting();
        app.UseOutputCache();

        // CRITICAL: Add session middleware before authentication for back-channel logout support
        app.UseSession();

        // NEW: enforce profile selection when multiple profiles configured
        app.UseMiddleware<ProfileSelectionMiddleware>();

        // Authentication and authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // CRITICAL: Add antiforgery middleware for Blazor components
        app.UseAntiforgery();

        // Add 403 Forbidden redirect middleware after authorization
        app.UseMiddleware<ForbiddenRedirectMiddleware>();

        // Token refresh middleware for API calls
        app.UseMiddleware<TokenRefreshMiddleware>();

        return app;
    }

    /// <summary>
    /// Configures authentication endpoints for login and logout
    /// </summary>
    public static WebApplication ConfigureAuthenticationEndpoints(this WebApplication app)
    {
        const string adminCookieScheme = "AdminCookies"; // Match the scheme from AddAuthenticationServices
        
        // Logout endpoint
        app.MapGet("/logout", async (HttpContext context, string? returnUrl = null) =>
        {
            var redirectUri = string.IsNullOrEmpty(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative) 
                ? "/signed-out" 
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