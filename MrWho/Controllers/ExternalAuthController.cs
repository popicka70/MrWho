using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;

namespace MrWho.Controllers;

[ApiController]
[Route("connect/external")] // Matches redirection endpoints configured in client registrations
public class ExternalAuthController : ControllerBase
{
    [HttpGet("callback")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Callback()
    {
        // Authenticate the result from the OpenIddict client
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded)
        {
            return Unauthorized();
        }

        // Principal contains claims from upstream IdP. Here you would:
        // - map claims
        // - find/create local user
        // - sign client-specific cookie
        // For now, just return basic info.
        var name = result.Principal?.Identity?.Name ?? result.Principal?.FindFirst("preferred_username")?.Value ?? result.Principal?.FindFirst("sub")?.Value;
        return Ok(new
        {
            Message = "External authentication succeeded",
            Name = name,
            Claims = result.Principal?.Claims.Select(c => new { c.Type, c.Value }).ToArray()
        });
    }

    [HttpGet("signout-callback")]
    [IgnoreAntiforgeryToken]
    public IActionResult SignoutCallback()
    {
        return Ok(new { Message = "External sign-out completed" });
    }
}
