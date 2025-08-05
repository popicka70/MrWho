using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

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
    /// Forces a token refresh for the current user
    /// </summary>
    public async Task<bool> ForceRefreshTokenAsync(HttpContext httpContext)
    {
        try
        {
            var refreshToken = await httpContext.GetTokenAsync("refresh_token");
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
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret
            };

            var tokenEndpoint = $"{authority.TrimEnd('/')}/connect/token";
            var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(tokenRequest));

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions 
                { 
                    PropertyNameCaseInsensitive = true 
                });

                if (tokenResponse?.AccessToken != null)
                {
                    // Update the authentication properties with new tokens
                    var authenticateResult = await httpContext.AuthenticateAsync();
                    if (authenticateResult.Properties != null)
                    {
                        authenticateResult.Properties.UpdateTokenValue("access_token", tokenResponse.AccessToken);
                        
                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            authenticateResult.Properties.UpdateTokenValue("refresh_token", tokenResponse.RefreshToken);
                        }

                        if (!string.IsNullOrEmpty(tokenResponse.IdToken))
                        {
                            authenticateResult.Properties.UpdateTokenValue("id_token", tokenResponse.IdToken);
                        }

                        // Calculate expiry time if provided
                        if (tokenResponse.ExpiresIn.HasValue)
                        {
                            var expiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn.Value);
                            authenticateResult.Properties.UpdateTokenValue("expires_at", 
                                expiresAt.ToString("o"));
                        }

                        // Sign in again with updated tokens
                        await httpContext.SignInAsync(authenticateResult.Principal!, authenticateResult.Properties);
                        
                        _logger.LogInformation("Token refresh successful");
                        return true;
                    }
                }
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Token refresh failed: {StatusCode} - {Error}", 
                    response.StatusCode, errorContent);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred during token refresh");
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
            var accessToken = await httpContext.GetTokenAsync("access_token");
            if (string.IsNullOrEmpty(accessToken))
            {
                _logger.LogDebug("No access token found, considering it expired");
                return true;
            }

            // Try to get expiry from stored token properties first
            var expiresAtString = await httpContext.GetTokenAsync("expires_at");
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
    /// DTO for token response from OpenIddict
    /// </summary>
    private class TokenResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public string? IdToken { get; set; }
        public string? TokenType { get; set; }
        public int? ExpiresIn { get; set; }
    }
}