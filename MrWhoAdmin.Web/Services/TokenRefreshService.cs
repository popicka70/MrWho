using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text.Json.Serialization;
using MrWho.Shared;

namespace MrWhoAdmin.Web.Services;

/// <summary>
/// Service for automatically refreshing authentication tokens
/// </summary>
public class TokenRefreshService : ITokenRefreshService
{
    private readonly ILogger<TokenRefreshService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;

    // Refresh token if it expires within this timeframe (5 minutes)
    private readonly TimeSpan _refreshBeforeExpiryTime = TimeSpan.FromMinutes(5);

    // Static lock to prevent concurrent refresh attempts across all instances
    private static readonly SemaphoreSlim _refreshSemaphore = new(1, 1);

    public TokenRefreshService(
        ILogger<TokenRefreshService> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
    }

    /// <summary>
    /// Checks if the current user's access token needs refreshing and refreshes it if necessary
    /// </summary>
    public async Task<bool> EnsureValidTokenAsync(HttpContext httpContext)
    {
        if (!httpContext.User.Identity?.IsAuthenticated == true)
        {
            _logger.LogDebug("User is not authenticated, no token refresh needed");
            return false;
        }

        if (await IsTokenExpiredOrExpiringSoonAsync(httpContext))
        {
            _logger.LogInformation("Access token is expired or expiring soon, attempting refresh");
            return await ForceRefreshTokenAsync(httpContext);
        }

        _logger.LogDebug("Access token is still valid, no refresh needed");
        return true;
    }

    /// <summary>
    /// Forces a token refresh for the current user with concurrency protection
    /// </summary>
    public async Task<bool> ForceRefreshTokenAsync(HttpContext httpContext, bool force = false)
    {
        return await RefreshTokenInternalAsync(httpContext, forceRefresh: force, updateCookies: true);
    }

    /// <summary>
    /// Attempts to refresh the token and triggers re-authentication if refresh fails
    /// </summary>
    public async Task<TokenRefreshResult> RefreshTokenWithReauthAsync(HttpContext httpContext, bool force = false)
    {
        var refreshSuccess = await RefreshTokenInternalAsync(httpContext, forceRefresh: force, updateCookies: true);
        
        if (refreshSuccess)
        {
            return new TokenRefreshResult { Success = true, RequiresReauth = false };
        }

        // Check if the failure was due to invalid refresh token
        var refreshToken = await httpContext.GetTokenAsync(TokenConstants.TokenNames.RefreshToken);
        if (string.IsNullOrEmpty(refreshToken))
        {
            _logger.LogWarning("No refresh token available, user needs to re-authenticate");
            return new TokenRefreshResult { Success = false, RequiresReauth = true, Reason = "No refresh token available" };
        }

        // Refresh failed - likely invalid/expired refresh token
        _logger.LogWarning("Token refresh failed, user needs to re-authenticate");
        return new TokenRefreshResult { Success = false, RequiresReauth = true, Reason = "Refresh token invalid or expired" };
    }

    /// <summary>
    /// Triggers re-authentication by clearing cookies and redirecting to login
    /// </summary>
    public async Task<IActionResult> TriggerReauthenticationAsync(HttpContext httpContext, string? returnUrl = null)
    {
        _logger.LogInformation("Triggering re-authentication for user");

        // Clear the current authentication cookies
        await httpContext.SignOutAsync();

        // Determine return URL
        var redirectUrl = !string.IsNullOrEmpty(returnUrl) && IsLocalUrl(httpContext, returnUrl) 
            ? returnUrl 
            : httpContext.Request.Path.ToString();

        // Trigger OpenID Connect challenge which will redirect to login
        var properties = new AuthenticationProperties
        {
            RedirectUri = redirectUrl
        };

        // Return challenge result that will redirect to OIDC provider
        return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme, properties);
    }

    /// <summary>
    /// Internal method to handle token refresh with options for different scenarios
    /// </summary>
    private async Task<bool> RefreshTokenInternalAsync(HttpContext httpContext, bool forceRefresh = false, bool updateCookies = true)
    {
        // Use semaphore to prevent concurrent refresh attempts
        if (!await _refreshSemaphore.WaitAsync(TimeSpan.FromSeconds(10)))
        {
            _logger.LogWarning("Timeout waiting for refresh token semaphore");
            return false;
        }

        try
        {
            // Double-check if token still needs refreshing after acquiring lock
            if (!await IsTokenExpiredOrExpiringSoonAsync(httpContext) && !forceRefresh)
            {
                _logger.LogDebug("Token was refreshed by another operation, no refresh needed");
                return true;
            }

            var refreshToken = await httpContext.GetTokenAsync(TokenConstants.TokenNames.RefreshToken);
            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("No refresh token available for token refresh");
                return false;
            }

            _logger.LogDebug("Attempting to refresh token using refresh token");

            var authConfig = _configuration.GetSection("Authentication");
            var authority = authConfig.GetValue<string>("Authority") ?? "https://localhost:7113/";
            var clientId = authConfig.GetValue<string>("ClientId") ?? "mrwho_admin_web";
            var clientSecret = authConfig.GetValue<string>("ClientSecret") ?? "MrWhoAdmin2024!SecretKey";

            using var httpClient = _httpClientFactory.CreateClient();
            
            var tokenRequest = new Dictionary<string, string>
            {
                [TokenConstants.ParameterNames.GrantType] = TokenConstants.GrantTypes.RefreshToken,
                [TokenConstants.ParameterNames.RefreshToken] = refreshToken,
                [TokenConstants.ParameterNames.ClientId] = clientId,
                [TokenConstants.ParameterNames.ClientSecret] = clientSecret
            };

            var tokenEndpoint = $"{authority.TrimEnd('/')}/connect/token";
            var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(tokenRequest));

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                _logger.LogDebug("Token response received: {Response}", responseContent);
                
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true 
                });

                if (tokenResponse?.AccessToken != null)
                {
                    // If we're not updating cookies (Blazor scenario) or response has started, just return success
                    if (!updateCookies || httpContext.Response.HasStarted)
                    {
                        _logger.LogInformation("Token refresh successful - cookies not updated (Blazor scenario or response started)");
                        return true;
                    }

                    // Update the authentication properties with new tokens
                    var authenticateResult = await httpContext.AuthenticateAsync();
                    if (authenticateResult.Properties != null)
                    {
                        authenticateResult.Properties.UpdateTokenValue(TokenConstants.TokenNames.AccessToken, tokenResponse.AccessToken);
                        
                        // CRITICAL: Update refresh token if a new one was provided (token rotation)
                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            authenticateResult.Properties.UpdateTokenValue(TokenConstants.TokenNames.RefreshToken, tokenResponse.RefreshToken);
                            _logger.LogDebug("Updated refresh token due to token rotation");
                        }

                        if (!string.IsNullOrEmpty(tokenResponse.IdToken))
                        {
                            authenticateResult.Properties.UpdateTokenValue(TokenConstants.TokenNames.IdToken, tokenResponse.IdToken);
                        }

                        // Calculate expiry time if provided
                        if (tokenResponse.ExpiresIn.HasValue)
                        {
                            var expiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn.Value);
                            authenticateResult.Properties.UpdateTokenValue(TokenConstants.TokenNames.ExpiresAt, 
                                expiresAt.ToString("o"));
                        }

                        // Only sign in if response hasn't started (to avoid header modification errors)
                        try
                        {
                            await httpContext.SignInAsync(authenticateResult.Principal!, authenticateResult.Properties);
                            _logger.LogInformation("Token refresh successful - cookies updated");
                        }
                        catch (InvalidOperationException ex) when (ex.Message.Contains("Headers are read-only"))
                        {
                            _logger.LogWarning("Token refresh successful but cookies could not be updated (response already started): {Error}", ex.Message);
                            return true;
                        }
                        
                        return true;
                    }
                }
                else
                {
                    _logger.LogWarning("Token response did not contain access_token: {Response}", responseContent);
                }
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Token refresh failed: {StatusCode} - {Error}", 
                    response.StatusCode, errorContent);
                
                // If the refresh token is invalid/expired, the user needs to re-authenticate
                if (response.StatusCode == System.Net.HttpStatusCode.BadRequest && 
                    errorContent.Contains(TokenConstants.ErrorCodes.InvalidGrant))
                {
                    _logger.LogWarning("Refresh token is invalid or expired, user needs to re-authenticate");
                    // The calling code should handle re-authentication based on the return value
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred during token refresh");
        }
        finally
        {
            _refreshSemaphore.Release();
        }

        return false;
    }

    /// <summary>
    /// Checks if the current access token is expired or will expire soon
    /// </summary>
    public async Task<bool> IsTokenExpiredOrExpiringSoonAsync(HttpContext httpContext)
    {
        try
        {
            var accessToken = await httpContext.GetTokenAsync(TokenConstants.TokenNames.AccessToken);
            if (string.IsNullOrEmpty(accessToken))
            {
                _logger.LogDebug("No access token found, considering it expired");
                return true;
            }

            // Try to get expiry from stored token properties first
            var expiresAtString = await httpContext.GetTokenAsync(TokenConstants.TokenNames.ExpiresAt);
            if (!string.IsNullOrEmpty(expiresAtString) && DateTimeOffset.TryParse(expiresAtString, out var expiresAt))
            {
                var timeUntilExpiry = expiresAt - DateTimeOffset.UtcNow;
                var isExpiringSoon = timeUntilExpiry <= _refreshBeforeExpiryTime;
                
                _logger.LogDebug("Token expires at {ExpiresAt}, time until expiry: {TimeUntilExpiry}, needs refresh: {NeedsRefresh}",
                    expiresAt, timeUntilExpiry, isExpiringSoon);
                
                return isExpiringSoon;
            }

            // Fallback: try to parse JWT token to get expiry
            var tokenHandler = new JwtSecurityTokenHandler();
            if (tokenHandler.CanReadToken(accessToken))
            {
                var jwtToken = tokenHandler.ReadJwtToken(accessToken);
                var expiry = jwtToken.ValidTo;
                var timeUntilExpiry = expiry - DateTime.UtcNow;
                var isExpiringSoon = timeUntilExpiry <= _refreshBeforeExpiryTime;
                
                _logger.LogDebug("JWT token expires at {ExpiresAt}, time until expiry: {TimeUntilExpiry}, needs refresh: {NeedsRefresh}",
                    expiry, timeUntilExpiry, isExpiringSoon);
                
                return isExpiringSoon;
            }

            _logger.LogWarning("Unable to determine token expiry, considering it expired");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking token expiry, considering it expired");
            return true;
        }
    }

    /// <summary>
    /// Validates if a URL is safe for local redirection
    /// </summary>
    private static bool IsLocalUrl(HttpContext httpContext, string url)
    {
        if (string.IsNullOrEmpty(url))
            return false;

        // Must be a relative URL (not absolute with protocol)
        if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return false;

        // Must start with / but not //
        return url.StartsWith("/") && !url.StartsWith("//");
    }

    /// <summary>
    /// DTO for token response from OpenIddict with correct JSON property names
    /// </summary>
    private class TokenResponse
    {
        [JsonPropertyName(TokenConstants.JsonPropertyNames.AccessToken)]
        public string? AccessToken { get; set; }
        
        [JsonPropertyName(TokenConstants.JsonPropertyNames.RefreshToken)]
        public string? RefreshToken { get; set; }
        
        [JsonPropertyName(TokenConstants.JsonPropertyNames.IdToken)]
        public string? IdToken { get; set; }
        
        [JsonPropertyName(TokenConstants.JsonPropertyNames.TokenType)]
        public string? TokenType { get; set; }
        
        [JsonPropertyName(TokenConstants.JsonPropertyNames.ExpiresIn)]
        public int? ExpiresIn { get; set; }
        
        [JsonPropertyName(TokenConstants.JsonPropertyNames.Scope)]
        public string? Scope { get; set; }
    }
}

/// <summary>
/// Result of token refresh operation
/// </summary>
public class TokenRefreshResult
{
    public bool Success { get; set; }
    public bool RequiresReauth { get; set; }
    public string? Reason { get; set; }
}