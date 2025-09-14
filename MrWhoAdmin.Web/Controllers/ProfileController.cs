using Microsoft.AspNetCore.Mvc;
using MrWhoAdmin.Web.Extensions;

namespace MrWhoAdmin.Web.Controllers;

[ApiExplorerSettings(IgnoreApi = true)]
public sealed class ProfileController : Controller
{
    private readonly IAdminProfileService _profiles;
    private readonly ILogger<ProfileController> _logger;

    public ProfileController(IAdminProfileService profiles, ILogger<ProfileController> logger)
    {
        _profiles = profiles;
        _logger = logger;
    }

    // GET /profile/select?name=local&returnUrl=/
    [HttpGet("/profile/select")]
    [IgnoreAntiforgeryToken]
    public IActionResult Select(string name, string? returnUrl = null)
    {
        if (string.IsNullOrWhiteSpace(name)) {
            return BadRequest("name required");
        }

        var profile = _profiles.Find(name);
        if (profile == null)
        {
            _logger.LogWarning("Profile select attempted for unknown profile {Profile}", name);
            return Redirect("/profiles");
        }
        _profiles.SetCurrentProfile(HttpContext, profile.Name);
        _logger.LogInformation("Profile {Profile} set via endpoint", profile.Name);
        var target = !string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/login";
        return Redirect(target);
    }
}
