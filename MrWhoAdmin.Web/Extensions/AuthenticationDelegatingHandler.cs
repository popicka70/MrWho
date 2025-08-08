using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using MrWhoAdmin.Web.Services;
using MrWho.Shared;
using System.Net;

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
                    
                    var refreshResult = await _tokenRefreshService.RefreshTokenWithReauthAsync(httpContext);
                    if (!refreshResult.Success)
                    {
                        if (refreshResult.RequiresReauth)
                        {
                            _logger.LogWarning("Token refresh failed with re-auth required before API call to {RequestUri}. Reason: {Reason}", 
                                request.RequestUri, refreshResult.Reason);
                            
                            // For API calls, we can't redirect to login, so return 401 to let the client handle it
                            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
                            {
                                Content = new StringContent($"Authentication required: {refreshResult.Reason}"),
                                ReasonPhrase = "Token refresh failed - re-authentication required"
                            };
                        }
                        else
                        {
                            _logger.LogWarning("Failed to refresh token before API call to {RequestUri}, proceeding with current token. Reason: {Reason}", 
                                request.RequestUri, refreshResult.Reason);
                            // Continue with existing token - the API might still accept it or we'll get a proper 401
                        }
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

        var response = await base.SendAsync(request, cancellationToken);
        
        // Handle authentication failures
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Received 401 Unauthorized response from {RequestUri} despite being authenticated. Token might be invalid.", 
                    request.RequestUri);
            }
            else if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                _logger.LogWarning("Received 403 Forbidden response from {RequestUri}. Session might be revoked or user lacks permissions.", 
                    request.RequestUri);
                
                // For API calls that result in 403, we should indicate this to the client
                // The client can then handle the redirect to logout/error page
                response.Headers.Add("X-Auth-Error", "session_revoked");
                response.Headers.Add("X-Auth-Error-Description", "Access forbidden - session may have been revoked");
            }
        }

        return response;
    }
}