using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Delegating handler that forwards the current authenticated user's access token (server-side scenarios).
/// </summary>
internal sealed class MrWhoUserAccessTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<MrWhoUserAccessTokenHandler> _logger;

    public MrWhoUserAccessTokenHandler(IHttpContextAccessor httpContextAccessor, ILogger<MrWhoUserAccessTokenHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var ctx = _httpContextAccessor.HttpContext;
        if (ctx?.User?.Identity?.IsAuthenticated == true)
        {
            var accessToken = await ctx.GetTokenAsync("access_token");
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            }
            else
            {
                _logger.LogDebug("User authenticated but no access token present in session.");
            }
        }
        return await base.SendAsync(request, cancellationToken);
    }
}
