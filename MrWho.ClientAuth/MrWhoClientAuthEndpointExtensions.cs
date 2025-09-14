using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace MrWho.ClientAuth;

/// <summary>
/// Endpoint mapping helpers for MrWho client applications.
/// </summary>
public static class MrWhoClientAuthEndpointExtensions
{
    /// <summary>
    /// Maps a compliant OpenID Connect Back-Channel Logout endpoint.
    /// Default route: "/signout-backchannel".
    /// </summary>
    /// <remarks>
    /// - Accepts POST with application/x-www-form-urlencoded containing "logout_token".
    /// - Parses spec-compliant JWT logout tokens and a lenient JSON fallback (for dev).
    /// - Signs out using the app's default sign-out or authenticate scheme (cookie).
    /// - Optionally caches logout info if IMemoryCache is registered.
    /// </remarks>
    public static IEndpointConventionBuilder MapMrWhoBackChannelLogoutEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/signout-backchannel")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (string.IsNullOrWhiteSpace(pattern)) {
            pattern = "/signout-backchannel";
        }

        return endpoints.MapPost(pattern, async context =>
        {
            var logger = context.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("MrWho.ClientAuth.BackChannelLogout");

            try
            {
                if (!context.Request.HasFormContentType)
                {
                    logger.LogWarning("Back-channel logout notification has invalid content type: {ContentType}", context.Request.ContentType);
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Invalid content type");
                    return;
                }

                var form = await context.Request.ReadFormAsync();
                var logoutToken = form["logout_token"].ToString();

                if (string.IsNullOrWhiteSpace(logoutToken))
                {
                    logger.LogWarning("Back-channel logout notification missing logout_token");
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Missing logout_token");
                    return;
                }

                string? subject = null;
                string? sessionId = null;

                // Try JWT parsing first (spec-compliant)
                if (logoutToken.Count(c => c == '.') == 2)
                {
                    try
                    {
                        var handler = new JwtSecurityTokenHandler();
                        var jwt = handler.ReadJwtToken(logoutToken);
                        subject = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                        sessionId = jwt.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;

                        if (!jwt.Payload.TryGetValue("events", out _))
                        {
                            logger.LogWarning("logout_token missing events claim");
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "Failed to parse logout_token as JWT, will try JSON fallback");
                    }
                }

                // Fallback: permissive JSON (dev mode, unsigned)
                if (subject is null && sessionId is null)
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(logoutToken);
                        var root = doc.RootElement;
                        if (root.TryGetProperty("sub", out var subEl)) {
                            subject = subEl.GetString();
                        }

                        if (root.TryGetProperty("sid", out var sidEl)) {
                            sessionId = sidEl.GetString();
                        }
                    }
                    catch (Exception jsonEx)
                    {
                        logger.LogError(jsonEx, "Failed to parse logout_token JSON");
                        context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        await context.Response.WriteAsync("Invalid logout_token");
                        return;
                    }
                }

                logger.LogInformation("Processing back-channel logout for subject: {Subject}, session: {SessionId}", subject, sessionId);

                // Cache logout info for a short time so the app can react if needed
                var cache = context.RequestServices.GetService<IMemoryCache>();
                if (!string.IsNullOrWhiteSpace(subject) && cache is not null)
                {
                    var logoutInfo = new
                    {
                        LoggedOutAt = DateTime.UtcNow,
                        Subject = subject,
                        SessionId = sessionId,
                        Reason = "BackChannelLogout"
                    };

                    cache.Set($"logout_{subject}", logoutInfo, TimeSpan.FromHours(1));
                    if (!string.IsNullOrWhiteSpace(sessionId)) {
                        cache.Set($"logout_session_{sessionId}", logoutInfo, TimeSpan.FromHours(1));
                    }
                }

                // Clear local authentication using default schemes
                var schemes = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
                var signOutScheme = await schemes.GetDefaultSignOutSchemeAsync() ?? await schemes.GetDefaultAuthenticateSchemeAsync();
                if (signOutScheme is not null)
                {
                    await context.SignOutAsync(signOutScheme.Name);
                }
                else
                {
                    // Fall back to default with no explicit scheme
                    await context.SignOutAsync();
                }

                // If session middleware is present, drop a marker (optional)
                try
                {
                    var sessionFeature = context.Features.Get<ISessionFeature>();
                    if (sessionFeature?.Session is not null)
                    {
                        var session = context.Session;
                        if (session.IsAvailable)
                        {
                            session.SetString("logout_notification", DateTime.UtcNow.ToString("O"));
                            if (!string.IsNullOrWhiteSpace(subject)) {
                                session.SetString("logout_subject", subject);
                            }

                            if (!string.IsNullOrWhiteSpace(sessionId)) {
                                session.SetString("logout_session_id", sessionId);
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore if session is not configured
                }

                logger.LogInformation("Back-channel logout processed successfully for subject: {Subject}", subject);
                context.Response.StatusCode = StatusCodes.Status200OK;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error processing back-channel logout notification");
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("Internal server error");
            }
        })
        .WithDisplayName("MrWho Back-Channel Logout");
    }
}
