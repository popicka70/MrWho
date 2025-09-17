using System.Data;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting; // added for RequireRateLimiting
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Endpoints;
using MrWho.Handlers;
using MrWho.Models; // added for UserProfile, UserState
using MrWho.Services;
using MrWho.Services.Mediator;
using MrWho.Shared;
using MrWho.Shared.Authentication; // for CookieSchemeNaming
using OpenIddict.Abstractions;
using OpenIddict.Client; // added for OpenIddictClientOptions/Registration
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using MrWho.Middleware; // re-added for DeviceAutoLoginMiddleware & ClientCookieMiddleware

namespace MrWho.Extensions;

public static class WebApplicationExtensions
{
    public static async Task<WebApplication> ConfigureMrWhoPipelineAsync(this WebApplication app)
    {
        app.MapDefaultEndpoints();

        // Configure the HTTP request pipeline
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        // Behind a reverse proxy (Railway, containers), honor X-Forwarded-* so Request.Scheme becomes https
        // Place this BEFORE redirection/auth so downstream sees the correct scheme/remote IP. Options are configured in DI.
        app.UseForwardedHeaders();

        // Allow disabling HTTPS redirection for containerized/internal HTTP calls
        var disableHttpsRedirect = string.Equals(Environment.GetEnvironmentVariable("DISABLE_HTTPS_REDIRECT"), "true", StringComparison.OrdinalIgnoreCase);
        if (!disableHttpsRedirect)
        {
            app.UseHttpsRedirection();
        }
        app.UseStaticFiles();

        app.UseRouting();

        // Strip bearer Authorization header for the authorize endpoint to avoid OpenIddict validation interfering with anonymous flows in tests
        app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                if (ctx.Request.Headers.ContainsKey("Authorization"))
                {
                    ctx.Request.Headers.Remove("Authorization");
                }
            }
            await next();
        });

        // Enable ASP.NET Core rate limiting middleware
        app.UseRateLimiter();

        // Enable session before custom middleware that uses it
        app.UseSession();

        // Device auto-login (silent) BEFORE normal auth so principal is established
        app.UseMiddleware<DeviceAutoLoginMiddleware>();

        // Client cookie middleware (requires session)
        app.UseMiddleware<ClientCookieMiddleware>();

        // Add antiforgery middleware
        app.UseAntiforgery();

        app.UseAuthentication();
        app.UseAuthorization();

        // Initialize database and apply EF Core migrations
        await app.InitializeDatabaseAsync();

        // Configure routing for controllers
        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        // CRITICAL: Map API controllers for token inspector and other API endpoints
        app.MapControllers();
        if (app.Environment.IsDevelopment())
        {
            app.MapDebugResyncClients();
        }

        return app;
    }

    /// <summary>
    /// Configures the MrWho pipeline with client-specific cookie support
    /// </summary>
    public static async Task<WebApplication> ConfigureMrWhoPipelineWithClientCookiesAsync(this WebApplication app)
    {
        app.MapDefaultEndpoints();

        // Configure the HTTP request pipeline
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        // Behind a reverse proxy (Railway, containers), honor X-Forwarded-* so Request.Scheme becomes https
        app.UseForwardedHeaders();

        var disableHttpsRedirect = string.Equals(Environment.GetEnvironmentVariable("DISABLE_HTTPS_REDIRECT"), "true", StringComparison.OrdinalIgnoreCase);
        if (!disableHttpsRedirect)
        {
            app.UseHttpsRedirection();
        }

        app.UseStaticFiles();
        app.UseRouting();

        // Strip bearer Authorization header for the authorize endpoint to avoid OpenIddict validation interfering with anonymous flows in tests
        app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase))
            {
                if (ctx.Request.Headers.ContainsKey("Authorization"))
                {
                    ctx.Request.Headers.Remove("Authorization");
                }
            }
            await next();
        });

        app.UseRateLimiter();

        app.UseSession();

        app.UseMiddleware<DeviceAutoLoginMiddleware>();

        app.UseMiddleware<ClientCookieMiddleware>();
        app.UseAntiforgery();

        app.UseAuthentication();
        app.UseAuthorization();

        await app.InitializeDatabaseAsync();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        app.MapControllers();
        if (app.Environment.IsDevelopment())
        {
            app.MapDebugResyncClients();
        }

        return app;
    }
}
