using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace MrWho.Services;

public sealed class AmrClaimsTransformation : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity id)
        {
            return Task.FromResult(principal);
        }

        var method = id.FindFirst(ClaimTypes.AuthenticationMethod)?.Value;
        if (!string.IsNullOrEmpty(method))
        {
            var hasAmr = id.Claims.Any(c => c.Type == "amr" && c.Value == method);
            if (!hasAmr)
            {
                id.AddClaim(new Claim("amr", method));
            }
        }

        return Task.FromResult(principal);
    }
}
