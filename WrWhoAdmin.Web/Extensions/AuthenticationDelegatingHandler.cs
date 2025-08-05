using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using MrWhoAdmin.Web.Services;

namespace MrWhoAdmin.Web.Extensions;

/// <summary>
/// Delegating handler to add authentication token to API requests with automatic token refresh
/// </summary>
public class AuthenticationDelegatingHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthenticationDelegatingHandler> _logger;
    private readonly ITokenRefreshService _tokenRefreshService;

    public AuthenticationDelegatingHandler(
        IHttpContextAccessor httpContextAccessor, 
        ILogger<AuthenticationDelegatingHandler> logger,
        ITokenRefreshService tokenRefreshService)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _tokenRefreshService = tokenRefreshService;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            try
            {
                // Ensure we have a valid token (refresh if needed)
                var hasValidToken = await _tokenRefreshService.EnsureValidTokenAsync(httpContext);
                if (!hasValidToken)
                {
                    _logger.LogWarning("Unable to obtain valid access token for request to {RequestUri}", request.RequestUri);
                    return await base.SendAsync(request, cancellationToken);
                }

                var accessToken = await httpContext.GetTokenAsync("access_token");
                if (!string.IsNullOrEmpty(accessToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    _logger.LogDebug("Added Bearer token to request: {RequestUri} (Token preview: {TokenPreview})", 
                        request.RequestUri, accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "...");
                }
                else
                {
                    _logger.LogWarning("No access token found after refresh attempt for request to {RequestUri}", request.RequestUri);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting or refreshing access token for request to {RequestUri}", request.RequestUri);
            }
        }
        else
        {
            _logger.LogDebug("User not authenticated, skipping token attachment for: {RequestUri}", request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}