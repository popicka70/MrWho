using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MrWho.Options;
using MrWho.Services;

namespace MrWho.Middleware;

/// <summary>
/// Middleware that performs silent sign-in using device auto-login token cookie when no user is authenticated.
/// Must run after session & BEFORE main auth (so we can set principal) OR after auth if we call SignIn manually with Identity scheme.
/// We choose: run after UseAuthentication so we only act when user unauthenticated, then sign-in and continue.
/// </summary>
public class DeviceAutoLoginMiddleware
{
    private readonly RequestDelegate _next;
    private const string CookieName = ".MrWho.DeviceAuth";
    private readonly ILogger<DeviceAutoLoginMiddleware> _logger;
    private readonly MrWhoOptions _options;

    public DeviceAutoLoginMiddleware(RequestDelegate next, ILogger<DeviceAutoLoginMiddleware> logger, IOptions<MrWhoOptions> options)
    { _next = next; _logger = logger; _options = options.Value; }

    public async Task InvokeAsync(HttpContext context, IDeviceAutoLoginService service, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        if (!_options.EnableDeviceAutoLogin)
        {
            await _next(context);
            return;
        }

        if (context.User?.Identity?.IsAuthenticated != true && context.Request.Cookies.TryGetValue(CookieName, out var rawToken) && !string.IsNullOrWhiteSpace(rawToken))
        {
            try
            {
                var result = await service.ValidateAsync(rawToken, context.RequestAborted);
                var user = result.user;
                var rotated = result.rotatedToken;
                var rotatedExp = result.rotatedExpires;
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: true);
                    _logger.LogDebug("Device auto-login succeeded for user {UserId}", user.Id);
                    if (rotated != null && rotatedExp != null)
                    {
                        context.Response.Cookies.Append(CookieName, rotated, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Lax,
                            Expires = rotatedExp
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Device auto-login failed");
            }
        }
        await _next(context);
    }
}
