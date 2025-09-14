using MrWhoAdmin.Web.Extensions;

namespace MrWhoAdmin.Web.Middleware;

/// <summary>
/// Ensures a profile is selected when multiple profiles are configured.
/// Redirects anonymously to /profiles before hitting protected routes or login.
/// Persists last visited URL in cookie so we can restore after profile selection.
/// </summary>
public sealed class ProfileSelectionMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly PathString ProfilesPath = new("/profiles");
    private static readonly PathString LoginPath = new("/login");

    public ProfileSelectionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, IAdminProfileService profileService)
    {
        var profiles = profileService.GetProfiles();
        if (profiles.Count > 1)
        {
            var current = profileService.GetCurrentProfile(context);
            var path = context.Request.Path;
            // Bypass for static, framework, and explicit profile/login endpoints
            if (current == null && !path.StartsWithSegments(ProfilesPath) && !path.StartsWithSegments(LoginPath) && !path.StartsWithSegments("/auth") && !path.StartsWithSegments("/css") && !path.StartsWithSegments("/js") && !path.StartsWithSegments("/_framework") && !path.StartsWithSegments("/images"))
            {
                // Persist last URL (only relative, exclude websockets, etc.)
                if (HttpMethods.IsGet(context.Request.Method) && !context.Request.Path.HasValue || context.Request.Path.Value != "/favicon.ico")
                {
                    var relative = context.Request.Path + context.Request.QueryString.ToUriComponent();
                    if (string.IsNullOrWhiteSpace(relative)) {
                        relative = "/";
                    }

                    context.Response.Cookies.Append(".MrWho.Admin.LastUrl", relative, new CookieOptions
                    {
                        HttpOnly = true,
                        SameSite = SameSiteMode.Lax,
                        Secure = context.Request.IsHttps,
                        Expires = DateTimeOffset.UtcNow.AddMinutes(30)
                    });
                }
                var dest = ProfilesPath + new PathString("?returnUrl=") + Uri.EscapeDataString(context.Request.Path + context.Request.QueryString);
                context.Response.Redirect(dest.ToString());
                return;
            }
        }
        await _next(context);
    }
}
