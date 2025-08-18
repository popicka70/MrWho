using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using MrWho.Options;

namespace MrWho.Controllers;

[ApiController]
[Route("debug")]
[AllowAnonymous]
public class DebugController : ControllerBase
{
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IOptionsMonitor<CookieAuthenticationOptions> _cookieOptions;
    private readonly MrWhoOptions _options;
    private readonly ILogger<DebugController> _logger;

    public DebugController(
        IAuthenticationSchemeProvider schemeProvider,
        IOptionsMonitor<CookieAuthenticationOptions> cookieOptions,
        IOptions<MrWhoOptions> options,
        ILogger<DebugController> logger)
    {
        _schemeProvider = schemeProvider;
        _cookieOptions = cookieOptions;
        _options = options.Value;
        _logger = logger;
    }

    [HttpGet("cookie-separation")]
    [HttpGet("client-cookies")]
    public async Task<IActionResult> GetCookieSeparationAsync()
    {
        var schemes = await _schemeProvider.GetAllSchemesAsync();

        // Collect cookie-related schemes and their configured cookie names
        var cookieSchemes = new List<object>();
        foreach (var s in schemes)
        {
            // Only include cookie authentication schemes (by handler type or known name pattern)
            if (s.HandlerType == typeof(CookieAuthenticationHandler) || s.Name.StartsWith("Identity.Application", StringComparison.Ordinal))
            {
                try
                {
                    var opts = _cookieOptions.Get(s.Name);
                    cookieSchemes.Add(new
                    {
                        name = s.Name,
                        displayName = s.DisplayName,
                        cookie = new
                        {
                            name = opts.Cookie?.Name,
                            sameSite = opts.Cookie?.SameSite.ToString(),
                            secure = opts.Cookie?.SecurePolicy.ToString(),
                            domain = opts.Cookie?.Domain,
                            path = opts.Cookie?.Path
                        },
                        expire = opts.ExpireTimeSpan,
                        sliding = opts.SlidingExpiration
                    });
                }
                catch (OptionsValidationException ex)
                {
                    _logger.LogDebug(ex, "Options not available for scheme {Scheme}", s.Name);
                    cookieSchemes.Add(new { name = s.Name, displayName = s.DisplayName, error = "Options not available" });
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to read options for scheme {Scheme}", s.Name);
                    cookieSchemes.Add(new { name = s.Name, displayName = s.DisplayName, error = ex.Message });
                }
            }
        }

        var presentCookies = HttpContext.Request.Cookies.Select(kvp => new { name = kvp.Key, valueLength = kvp.Value?.Length ?? 0 }).ToList();

        var result = new
        {
            mode = _options.CookieSeparationMode.ToString(),
            cookieSchemes,
            presentCookies
        };

        return Ok(result);
    }
}
