using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MrWho.ClientAuth.M2M;

/// <summary>
/// Delegating handler that forwards the current authenticated user's access token (server-side scenarios).
/// Supports optional automatic refresh (refresh_token) and automatic OIDC challenge on downstream 401.
/// </summary>
internal sealed class MrWhoUserAccessTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<MrWhoUserAccessTokenHandler> _logger;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptions;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly MrWhoUserAccessTokenHandlerOptions _options;

    public MrWhoUserAccessTokenHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<MrWhoUserAccessTokenHandler> logger,
        IAuthenticationSchemeProvider schemeProvider,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
        IOptions<MrWhoUserAccessTokenHandlerOptions> options,
        IHttpClientFactory httpClientFactory)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _schemeProvider = schemeProvider;
        _oidcOptions = oidcOptions;
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var ctx = _httpContextAccessor.HttpContext;
        if (ctx?.User?.Identity?.IsAuthenticated == true)
        {
            string? accessToken;
            if (_options.EnableAutomaticRefresh)
            {
                accessToken = await EnsureFreshAccessTokenAsync(ctx, cancellationToken);
            }
            else
            {
                accessToken = await ctx.GetTokenAsync("access_token");
            }

            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }
            else
            {
                _logger.LogDebug("User authenticated but no access token present in session.");
            }
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (_options.ChallengeOnUnauthorized && response.StatusCode == System.Net.HttpStatusCode.Unauthorized && ctx?.User?.Identity?.IsAuthenticated == true)
        {
            if (!ctx.Response.HasStarted)
            {
                _logger.LogInformation("Downstream API returned 401 for user {Sub}. Triggering OIDC challenge.", ctx.User.FindFirst("sub")?.Value);
                await ctx.ChallengeAsync();
            }
        }

        return response;
    }

    private async Task<string?> EnsureFreshAccessTokenAsync(HttpContext ctx, CancellationToken ct)
    {
        var accessToken = await ctx.GetTokenAsync("access_token");
        var expiresAtStr = await ctx.GetTokenAsync("expires_at");
        if (!DateTimeOffset.TryParse(expiresAtStr, out var expiresAtUtc))
        {
            return accessToken;
        }

        if (DateTimeOffset.UtcNow.Add(_options.RefreshSkew) < expiresAtUtc)
        {
            return accessToken;
        }

        var refreshToken = await ctx.GetTokenAsync("refresh_token");
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            _logger.LogDebug("Access token near/at expiry but no refresh_token available.");
            return accessToken;
        }

        try
        {
            var (cookieScheme, oidcScheme) = await ResolveSchemesAsync();
            var oidc = _oidcOptions.Get(oidcScheme);
            var authority = oidc.Authority?.TrimEnd('/') ?? string.Empty;
            if (string.IsNullOrEmpty(authority))
            {
                _logger.LogWarning("Cannot refresh token: OIDC authority missing.");
                return accessToken;
            }

            var tokenEndpoint = $"{authority}/connect/token"; // standard endpoint
            var client = oidc.BackchannelHttpHandler != null
                ? new HttpClient(oidc.BackchannelHttpHandler, disposeHandler: false)
                : _httpClientFactory.CreateClient();

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            };
            if (!string.IsNullOrEmpty(oidc.ClientId)) form["client_id"] = oidc.ClientId;
            if (!string.IsNullOrEmpty(oidc.ClientSecret)) form["client_secret"] = oidc.ClientSecret;

            using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = new FormUrlEncodedContent(form) };
            using var resp = await client.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                _logger.LogWarning("Refresh token request failed: {Status} {Body}", (int)resp.StatusCode, body);
                return accessToken;
            }

            var json = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var newAccessToken = doc.RootElement.TryGetProperty("access_token", out var atEl) ? atEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(newAccessToken))
            {
                _logger.LogWarning("Refresh response missing access_token.");
                return accessToken; // keep existing (may be null)
            }
            var newRefreshToken = doc.RootElement.TryGetProperty("refresh_token", out var rtEl) ? rtEl.GetString() : refreshToken;
            var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var expEl) ? expEl.GetInt32() : 3600;
            var newExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);

            var authResult = await ctx.AuthenticateAsync(cookieScheme);
            if (authResult.Succeeded && authResult.Properties != null)
            {
                // Only update tokens when we have non-null values (satisfies nullable annotations on UpdateTokenValue)
                authResult.Properties.UpdateTokenValue("access_token", newAccessToken);
                if (!string.IsNullOrWhiteSpace(newRefreshToken))
                {
                    authResult.Properties.UpdateTokenValue("refresh_token", newRefreshToken);
                }
                authResult.Properties.UpdateTokenValue("expires_at", newExpiresAt.ToString("o"));
                await ctx.SignInAsync(cookieScheme, authResult.Principal!, authResult.Properties);
                _logger.LogDebug("Refreshed user access token; new expiry {Expiry}", newExpiresAt);
                return newAccessToken;
            }
            _logger.LogWarning("Failed to persist refreshed token (scheme {Scheme}).", cookieScheme);
            return newAccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing user access token");
            return accessToken;
        }
    }

    private async Task<(string cookieScheme, string oidcScheme)> ResolveSchemesAsync()
    {
        var defaultAuthenticate = await _schemeProvider.GetDefaultAuthenticateSchemeAsync();
        var defaultChallenge = await _schemeProvider.GetDefaultChallengeSchemeAsync();
        var cookie = defaultAuthenticate?.Name ?? MrWhoClientAuthDefaults.CookieScheme;
        var oidc = defaultChallenge?.Name ?? MrWhoClientAuthDefaults.OpenIdConnectScheme;
        return (cookie, oidc);
    }
}
