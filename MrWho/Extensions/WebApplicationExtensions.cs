using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Services;
using MrWho.Services.Mediator;
using MrWho.Endpoints;
using MrWho.Middleware;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using static OpenIddict.Abstractions.OpenIddictConstants;
using MrWho.Shared;
using Microsoft.AspNetCore.HttpOverrides;
using MrWho.Models; // added for UserProfile, UserState
using System.Data;
using Microsoft.AspNetCore.RateLimiting; // added for RequireRateLimiting
using OpenIddict.Client.AspNetCore;
using OpenIddict.Client; // added for OpenIddictClientOptions/Registration

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

        // Enable ASP.NET Core rate limiting middleware
        app.UseRateLimiter();

        // Enable session before custom middleware that uses it
        app.UseSession();

        // Add client cookie middleware before authentication
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

        // Map OpenIddict client redirection endpoints
        app.MapGet("/connect/external/login/{provider}", async (HttpContext http, string provider, IOptionsMonitor<OpenIddictClientOptions> options) =>
        {
            var registrations = options.CurrentValue.Registrations;

            // Try resolve by ProviderName (case-insensitive)
            var registration = registrations.FirstOrDefault(r =>
                !string.IsNullOrWhiteSpace(r.ProviderName) &&
                string.Equals(r.ProviderName, provider, StringComparison.OrdinalIgnoreCase));

            // Fallback: try resolve by Issuer host or absolute URI text
            registration ??= registrations.FirstOrDefault(r =>
                r.Issuer is not null && (
                    string.Equals(r.Issuer.Host, provider, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Issuer.AbsoluteUri.TrimEnd('/'), provider.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)));

            // Fallback: try resolve by RegistrationId
            registration ??= registrations.FirstOrDefault(r =>
                !string.IsNullOrWhiteSpace(r.RegistrationId) &&
                string.Equals(r.RegistrationId, provider, StringComparison.OrdinalIgnoreCase));

            if (registration is null)
            {
                http.Response.StatusCode = StatusCodes.Status400BadRequest;
                await http.Response.WriteAsync($"Unknown external provider '{provider}'."); // updated error message
                return;
            }

            // Carry original authorize request context so callback can resume the flow
            var returnUrl = http.Request.Query["returnUrl"].ToString();
            var clientId = http.Request.Query["clientId"].ToString();
            var force = http.Request.Query["force"].ToString();

            var props = new AuthenticationProperties
            {
                RedirectUri = "/connect/external/callback"
            };

            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                props.Items["returnUrl"] = returnUrl;
            }
            if (!string.IsNullOrWhiteSpace(clientId))
            {
                props.Items["clientId"] = clientId;
            }

            // Preserve registration id in a custom item that roundtrips in state
            props.Items["extRegistrationId"] = registration.RegistrationId;

            // Use RegistrationId to unambiguously select the configured client
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = registration.RegistrationId;

            // Optional: force re-auth at the external provider
            if (!string.IsNullOrEmpty(force) && (force == "1" || force.Equals("true", StringComparison.OrdinalIgnoreCase)))
            {
                props.Parameters["prompt"] = "login";
                props.Parameters["max_age"] = 0;
            }

            await http.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
        }).AllowAnonymous();

        // Endpoint to sign out from the last-used external provider
        app.MapGet("/connect/external/signout", async (HttpContext http) =>
        {
            var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ExternalSignout");
            var regId = http.Session.GetString("ExternalRegistrationId");
            if (string.IsNullOrWhiteSpace(regId))
            {
                logger.LogDebug("No external RegistrationId in session; skipping external sign-out");
                http.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            var props = new AuthenticationProperties
            {
                // After provider sign-out completes, return here and clear the session marker
                RedirectUri = "/connect/external/signout-callback"
            };
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = regId;

            // Ask the OpenIddict client to sign the user out from the remote provider
            await http.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
        }).AllowAnonymous();

        app.MapGet("/connect/external/signout-callback", async (HttpContext http) =>
        {
            try { http.Session.Remove("ExternalRegistrationId"); } catch { }
            var resume = http.Session.GetString("ExternalSignoutResumeUrl");
            if (!string.IsNullOrWhiteSpace(resume))
            {
                http.Session.Remove("ExternalSignoutResumeUrl");
                http.Response.Redirect(resume);
                return;
            }
            http.Response.StatusCode = StatusCodes.Status204NoContent;
            await Task.CompletedTask; // Ensure async completion
        }).AllowAnonymous();

        // Map OIDC authorize endpoint for OpenIddict passthrough
        app.MapMethods("/connect/authorize", new[] { "GET", "POST" }, async (HttpContext http, IMediator mediator) =>
        {
            return await mediator.Send(new OidcAuthorizeRequest(http));
        }).AllowAnonymous();

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

        app.UseRateLimiter();

        // Enable session before custom middleware that uses it
        app.UseSession();

        app.UseMiddleware<ClientCookieMiddleware>();
        app.UseAntiforgery();

        app.UseAuthentication();
        app.UseAuthorization();

        await app.InitializeDatabaseAsync();

        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        app.MapControllers();

        // Map OpenIddict client redirection endpoints
        app.MapGet("/connect/external/login/{provider}", async (HttpContext http, string provider, IOptionsMonitor<OpenIddictClientOptions> options) =>
        {
            var registrations = options.CurrentValue.Registrations;

            // Try resolve by ProviderName (case-insensitive)
            var registration = registrations.FirstOrDefault(r =>
                !string.IsNullOrWhiteSpace(r.ProviderName) &&
                string.Equals(r.ProviderName, provider, StringComparison.OrdinalIgnoreCase));

            // Fallback: try resolve by Issuer host or absolute URI text
            registration ??= registrations.FirstOrDefault(r =>
                r.Issuer is not null && (
                    string.Equals(r.Issuer.Host, provider, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Issuer.AbsoluteUri.TrimEnd('/'), provider.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)));

            // Fallback: try resolve by RegistrationId
            registration ??= registrations.FirstOrDefault(r =>
                !string.IsNullOrWhiteSpace(r.RegistrationId) &&
                string.Equals(r.RegistrationId, provider, StringComparison.OrdinalIgnoreCase));

            if (registration is null)
            {
                http.Response.StatusCode = StatusCodes.Status400BadRequest;
                await http.Response.WriteAsync($"Unknown external provider '{provider}'."); // updated error message
                return;
            }

            // Carry original authorize request context so callback can resume the flow
            var returnUrl = http.Request.Query["returnUrl"].ToString();
            var clientId = http.Request.Query["clientId"].ToString();
            var force = http.Request.Query["force"].ToString();

            var props = new AuthenticationProperties
            {
                RedirectUri = "/connect/external/callback"
            };

            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                props.Items["returnUrl"] = returnUrl;
            }
            if (!string.IsNullOrWhiteSpace(clientId))
            {
                props.Items["clientId"] = clientId;
            }

            // Preserve registration id in a custom item that roundtrips in state
            props.Items["extRegistrationId"] = registration.RegistrationId;

            // Use RegistrationId to unambiguously select the configured client
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = registration.RegistrationId;

            // Optional: force re-auth at the external provider
            if (!string.IsNullOrEmpty(force) && (force == "1" || force.Equals("true", StringComparison.OrdinalIgnoreCase)))
            {
                props.Parameters["prompt"] = "login";
                props.Parameters["max_age"] = 0;
            }

            await http.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
        }).AllowAnonymous();

        // Endpoint to sign out from the last-used external provider
        app.MapGet("/connect/external/signout", async (HttpContext http) =>
        {
            var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ExternalSignout");
            var regId = http.Session.GetString("ExternalRegistrationId");
            if (string.IsNullOrWhiteSpace(regId))
            {
                logger.LogDebug("No external RegistrationId in session; skipping external sign-out");
                http.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            var props = new AuthenticationProperties
            {
                // After provider sign-out completes, return here and clear the session marker
                RedirectUri = "/connect/external/signout-callback"
            };
            props.Items[OpenIddictClientAspNetCoreConstants.Properties.RegistrationId] = regId;

            // Ask the OpenIddict client to sign the user out from the remote provider
            await http.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, props);
        }).AllowAnonymous();

        app.MapGet("/connect/external/signout-callback", async (HttpContext http) =>
        {
            try { http.Session.Remove("ExternalRegistrationId"); } catch { }
            var resume = http.Session.GetString("ExternalSignoutResumeUrl");
            if (!string.IsNullOrWhiteSpace(resume))
            {
                http.Session.Remove("ExternalSignoutResumeUrl");
                http.Response.Redirect(resume);
                return;
            }
            http.Response.StatusCode = StatusCodes.Status204NoContent;
            await Task.CompletedTask; // Ensure async completion
        }).AllowAnonymous();

        // Map OIDC authorize endpoint for OpenIddict passthrough
        app.MapMethods("/connect/authorize", new[] { "GET", "POST" }, async (HttpContext http, IMediator mediator) =>
        {
            return await mediator.Send(new OidcAuthorizeRequest(http));
        }).AllowAnonymous();

        return app;
    }
}