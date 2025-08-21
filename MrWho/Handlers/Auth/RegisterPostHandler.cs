using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Services;
using MrWho.Services.Mediator;
using MrWho.Shared.Models;

namespace MrWho.Handlers.Auth;

public sealed class RegisterPostHandler : IRequestHandler<MrWho.Endpoints.Auth.RegisterPostRequest, IActionResult>
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly ILoginHelper _loginHelper;

    public RegisterPostHandler(UserManager<IdentityUser> userManager, ApplicationDbContext db, ILoginHelper loginHelper)
    {
        _userManager = userManager;
        _db = db;
        _loginHelper = loginHelper;
    }

    public async Task<IActionResult> Handle(MrWho.Endpoints.Auth.RegisterPostRequest request, CancellationToken cancellationToken)
    {
        var http = request.HttpContext;
        var input = request.Input;

        var token = http.Request.Form["recaptchaToken"].ToString();
        var recaptchaOk = await _loginHelper.VerifyRecaptchaAsync(http, token, "register");
        if (!recaptchaOk)
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey()
            };
            vd.ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        // Required field validation with proper ModelState errors
        if (string.IsNullOrWhiteSpace(input.Email) || string.IsNullOrWhiteSpace(input.Password) || string.IsNullOrWhiteSpace(input.FirstName) || string.IsNullOrWhiteSpace(input.LastName))
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey()
            };
            if (string.IsNullOrWhiteSpace(input.Email)) vd.ModelState.AddModelError("Email", "Email is required.");
            if (string.IsNullOrWhiteSpace(input.Password)) vd.ModelState.AddModelError("Password", "Password is required.");
            if (string.IsNullOrWhiteSpace(input.FirstName)) vd.ModelState.AddModelError("FirstName", "First name is required.");
            if (string.IsNullOrWhiteSpace(input.LastName)) vd.ModelState.AddModelError("LastName", "Last name is required.");
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        var existingByEmail = await _userManager.FindByEmailAsync(input.Email);
        if (existingByEmail != null)
        {
            var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
            {
                ["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey()
            };
            vd.ModelState.AddModelError("Email", "An account with this email already exists.");
            return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
        }

        // Begin transaction to ensure user, profile and client link are consistent
        await using var tx = await _db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            var user = new IdentityUser { UserName = input.Email, Email = input.Email, EmailConfirmed = false };
            var createResult = await _userManager.CreateAsync(user, input.Password);
            if (!createResult.Succeeded)
            {
                var vd = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    ["RecaptchaSiteKey"] = _loginHelper.GetRecaptchaSiteKey()
                };
                foreach (var error in createResult.Errors)
                {
                    var code = error.Code ?? string.Empty;
                    if (code.Contains("Password", StringComparison.OrdinalIgnoreCase)) vd.ModelState.AddModelError("Password", error.Description);
                    else if (code.Contains("Email", StringComparison.OrdinalIgnoreCase) || code.Contains("UserName", StringComparison.OrdinalIgnoreCase)) vd.ModelState.AddModelError("Email", error.Description);
                    else vd.ModelState.AddModelError(string.Empty, error.Description);
                }
                return new ViewResult { ViewName = "Register", ViewData = new ViewDataDictionary(vd) { Model = input } };
            }

            var profile = new MrWho.Models.UserProfile
            {
                UserId = user.Id,
                FirstName = input.FirstName,
                LastName = input.LastName,
                DisplayName = $"{input.FirstName} {input.LastName}".Trim(),
                State = MrWho.Models.UserState.New,
                CreatedAt = DateTime.UtcNow
            };
            _db.UserProfiles.Add(profile);
            await _db.SaveChangesAsync(cancellationToken);

            // Link user to client if we have a hint (either direct clientId or via returnUrl's client_id)
            var formClientId = http.Request.Form["clientId"].ToString();
            var returnUrl = http.Request.Form["returnUrl"].ToString();
            var clientHint = !string.IsNullOrWhiteSpace(formClientId) ? formClientId : _loginHelper.TryExtractClientIdFromReturnUrl(returnUrl);
            if (!string.IsNullOrWhiteSpace(clientHint))
            {
                var client = await _db.Clients.FirstOrDefaultAsync(c => c.Id == clientHint || c.ClientId == clientHint, cancellationToken);
                if (client != null)
                {
                    var exists = await _db.ClientUsers.AnyAsync(cu => cu.ClientId == client.Id && cu.UserId == user.Id, cancellationToken);
                    if (!exists)
                    {
                        _db.ClientUsers.Add(new ClientUser
                        {
                            ClientId = client.Id,
                            UserId = user.Id,
                            CreatedAt = DateTime.UtcNow,
                            CreatedBy = user.UserName
                        });
                        await _db.SaveChangesAsync(cancellationToken);
                    }
                }
            }

            await tx.CommitAsync(cancellationToken);
        }
        catch
        {
            await tx.RollbackAsync(cancellationToken);
            throw;
        }

        // Preserve original query params on redirect so success page can offer a proper Login link
        var redirectRouteValues = new { returnUrl = http.Request.Form["returnUrl"].ToString(), clientId = http.Request.Form["clientId"].ToString() };
        return new RedirectToActionResult("RegisterSuccess", "Auth", redirectRouteValues);
    }
}
