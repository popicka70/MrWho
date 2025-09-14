using Microsoft.AspNetCore.Authentication;

namespace MrWhoDemo1.Middleware;

/// <summary>
/// Middleware to validate tokens on each request and handle revoked sessions
/// </summary>
public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TokenValidationMiddleware> _logger;

    public TokenValidationMiddleware(RequestDelegate next, ILogger<TokenValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only validate for authenticated requests to protected resources
        if (context.User.Identity?.IsAuthenticated == true &&
            IsProtectedResource(context) &&
            !context.Response.HasStarted)
        {
            try
            {
                await ValidateTokenAsync(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token validation");
            }
        }

        await _next(context);
    }

    private async Task ValidateTokenAsync(HttpContext context)
    {
        try
        {
            // Get the stored access token
            var accessToken = await context.GetTokenAsync("access_token");

            if (string.IsNullOrEmpty(accessToken))
            {
                _logger.LogWarning("No access token found for authenticated user, signing out");
                await SignOutUserAsync(context);
                return;
            }

            // Make a quick call to the OIDC server to validate the token
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // Call a simple endpoint that requires authentication
            var response = await httpClient.GetAsync("https://localhost:7113/connect/userinfo");

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogWarning("Access token is invalid or revoked, signing out user");
                await SignOutUserAsync(context);
                return;
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Token validation failed with status: {StatusCode}", response.StatusCode);
                // Don't sign out for other errors (network issues, etc.)
                return;
            }

            _logger.LogDebug("Token validation successful");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "Network error during token validation, allowing request to continue");
            // Don't sign out due to network errors
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning(ex, "Token validation timed out, allowing request to continue");
            // Don't sign out due to timeouts
        }
    }

    private async Task SignOutUserAsync(HttpContext context)
    {
        _logger.LogInformation("Signing out user due to invalid/revoked token");

        // Sign out from the local cookie scheme
        await context.SignOutAsync("Demo1Cookies");

        // Redirect to login page with a message
        var returnUrl = Uri.EscapeDataString(context.Request.Path + context.Request.QueryString);
        context.Response.Redirect($"/Account/Login?returnUrl={returnUrl}&reason=session_revoked");
    }

    private static bool IsProtectedResource(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant();

        // Skip validation for:
        // - Static files
        // - Authentication endpoints
        // - Debug endpoints
        // - Health checks
        if (path != null && (
            path.StartsWith("/css/") ||
            path.StartsWith("/js/") ||
            path.StartsWith("/lib/") ||
            path.StartsWith("/images/") ||
            path.StartsWith("/account/") ||
            path.StartsWith("/debug/") ||
            path.StartsWith("/health") ||
            path.EndsWith(".css") ||
            path.EndsWith(".js") ||
            path.EndsWith(".ico") ||
            path.EndsWith(".png") ||
            path.EndsWith(".jpg") ||
            path.EndsWith(".gif") ||
            path.EndsWith(".svg")))
        {
            return false;
        }

        return true;
    }
}