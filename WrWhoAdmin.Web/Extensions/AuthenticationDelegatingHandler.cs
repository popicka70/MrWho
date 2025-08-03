using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;

namespace MrWhoAdmin.Web.Extensions;

/// <summary>
/// Delegating handler to add authentication token to API requests
/// </summary>
public class AuthenticationDelegatingHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthenticationDelegatingHandler> _logger;

    public AuthenticationDelegatingHandler(IHttpContextAccessor httpContextAccessor, ILogger<AuthenticationDelegatingHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            try
            {
                var accessToken = await httpContext.GetTokenAsync("access_token");
                if (!string.IsNullOrEmpty(accessToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    _logger.LogDebug("Added Bearer token to request: {RequestUri} (Token preview: {TokenPreview})", 
                        request.RequestUri, accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "...");
                }
                else
                {
                    _logger.LogWarning("No access token found for authenticated user - checking available tokens");
                    
                    // Log available token names for debugging
                    var tokens = await httpContext.GetTokenAsync("id_token");
                    _logger.LogDebug("Available tokens - ID Token: {HasIdToken}", !string.IsNullOrEmpty(tokens));
                    
                    var refreshToken = await httpContext.GetTokenAsync("refresh_token");
                    _logger.LogDebug("Available tokens - Refresh Token: {HasRefreshToken}", !string.IsNullOrEmpty(refreshToken));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting access token for request to {RequestUri}", request.RequestUri);
            }
        }
        else
        {
            _logger.LogDebug("User not authenticated, skipping token attachment for: {RequestUri}", request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}