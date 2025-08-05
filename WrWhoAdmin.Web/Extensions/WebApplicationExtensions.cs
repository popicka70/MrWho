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
        // Map authentication endpoints
        app.MapGet("/login", async (HttpContext context, string? returnUrl = null) =>
        {
            await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = returnUrl ?? "/"
                });
        });

        app.MapGet("/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        });

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