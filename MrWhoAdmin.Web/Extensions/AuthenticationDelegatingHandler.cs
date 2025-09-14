using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using MrWho.Shared;
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
        var stopwatch = Stopwatch.StartNew();
        var requestId = Guid.NewGuid().ToString("N")[..8];

        _logger.LogDebug("Starting HTTP request {RequestId} to {RequestUri}", requestId, request.RequestUri);

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
                    _logger.LogDebug("Added Bearer token to request {RequestId}: {RequestUri} (Token preview: {TokenPreview})",
                        requestId, request.RequestUri, accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "...");
                }
                else
                {
                    _logger.LogWarning("No access token available for request {RequestId} to {RequestUri}", requestId, request.RequestUri);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting or refreshing access token for request {RequestId} to {RequestUri}", requestId, request.RequestUri);
                // Continue without token - let the API respond with appropriate error
            }
        }
        else
        {
            _logger.LogDebug("User not authenticated, skipping token attachment for request {RequestId}: {RequestUri}", requestId, request.RequestUri);
        }

        HttpResponseMessage response;
        try
        {
            // Send the request with proper timeout and cancellation handling
            response = await base.SendAsync(request, cancellationToken);

            stopwatch.Stop();
            _logger.LogDebug("HTTP request {RequestId} completed in {ElapsedMs}ms with status {StatusCode}",
                requestId, stopwatch.ElapsedMilliseconds, response.StatusCode);
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException || cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            _logger.LogWarning("Request {RequestId} to {RequestUri} was cancelled or timed out after {ElapsedMs}ms. CancellationRequested: {CancellationRequested}",
                requestId, request.RequestUri, stopwatch.ElapsedMilliseconds, cancellationToken.IsCancellationRequested);

            // Return a proper timeout response instead of letting the exception bubble up
            return new HttpResponseMessage(HttpStatusCode.RequestTimeout)
            {
                Content = new StringContent("Request timed out"),
                ReasonPhrase = "Request timeout"
            };
        }
        catch (TaskCanceledException ex)
        {
            stopwatch.Stop();
            _logger.LogWarning(ex, "Request {RequestId} to {RequestUri} was cancelled unexpectedly after {ElapsedMs}ms",
                requestId, request.RequestUri, stopwatch.ElapsedMilliseconds);

            // Check if this is a cancellation token issue or actual timeout
            if (cancellationToken.IsCancellationRequested)
            {
                return new HttpResponseMessage(HttpStatusCode.RequestTimeout)
                {
                    Content = new StringContent("Request was cancelled"),
                    ReasonPhrase = "Request cancelled"
                };
            }

            // For other cancellation scenarios, return service unavailable
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent("Service temporarily unavailable"),
                ReasonPhrase = "Service unavailable"
            };
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "Network error during request {RequestId} to {RequestUri} after {ElapsedMs}ms",
                requestId, request.RequestUri, stopwatch.ElapsedMilliseconds);

            // Return a proper network error response
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent($"Network error: {ex.Message}"),
                ReasonPhrase = "Network error"
            };
        }
        catch (ObjectDisposedException ex)
        {
            stopwatch.Stop();
            _logger.LogWarning(ex, "Connection was disposed during request {RequestId} to {RequestUri} after {ElapsedMs}ms",
                requestId, request.RequestUri, stopwatch.ElapsedMilliseconds);

            // Return a proper connection error response
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent("Connection was closed unexpectedly"),
                ReasonPhrase = "Connection disposed"
            };
        }

        // Handle authentication failures
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Received 401 Unauthorized response from request {RequestId} to {RequestUri} despite being authenticated. Token might be invalid.",
                    requestId, request.RequestUri);
            }
            else if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                _logger.LogWarning("Received 403 Forbidden response from request {RequestId} to {RequestUri}. Session might be revoked or user lacks permissions.",
                    requestId, request.RequestUri);

                // For API calls that result in 403, we should indicate this to the client
                // The client can then handle the redirect to logout/error page
                response.Headers.Add("X-Auth-Error", "session_revoked");
                response.Headers.Add("X-Auth-Error-Description", "Access forbidden - session may have been revoked");
            }
        }

        return response;
    }
}