using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;

namespace MrWho.ApiService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TestController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult PublicEndpoint()
    {
        return Ok(new 
        { 
            message = "This is a public endpoint - no authentication required",
            timestamp = DateTime.UtcNow
        });
    }

    [HttpGet("protected")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult ProtectedEndpoint()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = User.FindFirst("preferred_username")?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        
        return Ok(new 
        { 
            message = "This is a protected endpoint - authentication required",
            user = new
            {
                id = userId,
                username = username,
                email = email,
                claims = User.Claims.Select(c => new { c.Type, c.Value })
            },
            timestamp = DateTime.UtcNow
        });
    }

    [HttpGet("user-info")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult GetUserInfo()
    {
        var claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);
        
        return Ok(new
        {
            subject = User.FindFirst("sub")?.Value,
            email = User.FindFirst("email")?.Value,
            emailVerified = User.FindFirst("email_verified")?.Value,
            preferredUsername = User.FindFirst("preferred_username")?.Value,
            givenName = User.FindFirst("given_name")?.Value,
            familyName = User.FindFirst("family_name")?.Value,
            name = User.FindFirst("name")?.Value,
            role = User.FindFirst("role")?.Value,
            allClaims = claims
        });
    }
}