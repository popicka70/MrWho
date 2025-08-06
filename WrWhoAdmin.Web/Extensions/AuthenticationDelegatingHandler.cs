using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using MrWhoAdmin.Web.Services;
using MrWho.Shared;

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
                // Check if we need to refresh the token before making the API call
                if (await _tokenRefreshService.IsTokenExpiredOrExpiringSoonAsync(httpContext))
                {
                    _logger.LogDebug("Access token is expired or expiring, attempting refresh before API call to {RequestUri}", request.RequestUri);
                    
                    var refreshSuccess = await _tokenRefreshService.ForceRefreshTokenAsync(httpContext);
                    if (!refreshSuccess)
                    {
                        _logger.LogWarning("Failed to refresh token before API call to {RequestUri}, proceeding with current token", request.RequestUri);
                        // Continue with existing token - the API might still accept it or we'll get a proper 401
                    }
                }

                var accessToken = await httpContext.GetTokenAsync(TokenConstants.TokenNames.AccessToken);
                if (!string.IsNullOrEmpty(accessToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue(TokenConstants.TokenTypes.Bearer, accessToken);
                    _logger.LogDebug("Added Bearer token to request: {RequestUri} (Token preview: {TokenPreview})", 
                        request.RequestUri, accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "...");
                }
                else
                {
                    _logger.LogWarning("No access token available for request to {RequestUri}", request.RequestUri);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting or refreshing access token for request to {RequestUri}", request.RequestUri);
                // Continue without token - let the API respond with appropriate error
            }
        }
        else
        {
            _logger.LogDebug("User not authenticated, skipping token attachment for: {RequestUri}", request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}