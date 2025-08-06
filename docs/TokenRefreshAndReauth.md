# Token Refresh and Re-Authentication

This document explains the enhanced token refresh system that automatically handles re-authentication when refresh tokens expire or become invalid.

## Overview

The system now provides automatic re-authentication when token refresh fails due to invalid or expired refresh tokens. This prevents users from getting stuck with authentication errors and provides a seamless experience.

## Key Components

### 1. Enhanced TokenRefreshService

The `TokenRefreshService` now includes methods to:
- Detect when re-authentication is required
- Trigger automatic re-authentication
- Handle both interactive and API scenarios

#### New Methods:
- `RefreshTokenWithReauthAsync()` - Attempts refresh and indicates if re-auth is needed
- `TriggerReauthenticationAsync()` - Clears cookies and redirects to login

### 2. Enhanced TokenRefreshMiddleware

The middleware now automatically handles re-authentication for interactive requests:
- Detects when refresh token is invalid
- Redirects to authentication controller for seamless re-login
- Only applies to major page navigations, not AJAX or API calls

### 3. AuthController

New controller providing authentication endpoints:
- `/auth/login` - Trigger login/challenge
- `/auth/logout` - Sign out user
- `/auth/check-and-reauth` - Check token and re-authenticate if needed
- `/auth/refresh` - Force token refresh
- `/auth/status` - Get authentication status (API)

### 4. BlazorAuthService

Service for handling authentication in Blazor components:
- `EnsureAuthenticatedAsync()` - Check auth status and trigger re-auth if needed
- `TriggerReauthenticationAsync()` - Manually trigger re-authentication
- `HasAuthenticationError()` - Check for auth errors in URL
- `GetAuthenticationErrorMessage()` - Get error details

### 5. AuthenticatedComponentBase

Base class for Blazor components that need authentication:
- Automatically checks authentication on initialization
- Provides loading states and error handling
- Handles authentication errors from URL parameters

## Usage Examples

### For Blazor Components

#### Option 1: Inherit from AuthenticatedComponentBase
```razor
@page "/my-page"
@inherits AuthenticatedComponentBase

<h3>My Protected Page</h3>

@if (IsLoading)
{
    @RenderAuthenticationStatus()
}
else if (IsAuthenticated)
{
    <p>Welcome! You are authenticated.</p>
    <!-- Your protected content here -->
}
else
{
    @RenderAuthenticationStatus()
}
```

#### Option 2: Use BlazorAuthService directly
```razor
@page "/my-page"
@inject IBlazorAuthService BlazorAuthService

@if (isLoading)
{
    <p>Loading...</p>
}
else if (!isAuthenticated)
{
    <div class="alert alert-warning">
        Authentication required.
        <button @onclick="LoginAsync" class="btn btn-primary">Login</button>
    </div>
}
else
{
    <!-- Your protected content -->
}

@code {
    private bool isLoading = true;
    private bool isAuthenticated = false;

    protected override async Task OnInitializedAsync()
    {
        isAuthenticated = await BlazorAuthService.EnsureAuthenticatedAsync();
        isLoading = false;
    }

    private async Task LoginAsync()
    {
        await BlazorAuthService.TriggerReauthenticationAsync();
    }
}
```

### For MVC Controllers/Pages

The middleware automatically handles re-authentication for MVC requests. If a refresh token is invalid, users will be automatically redirected to login.

### For API Calls

The `AuthenticationDelegatingHandler` automatically handles token refresh for HTTP client requests. If refresh fails, it returns a 401 response that client code can handle.

```csharp
// In a service that makes API calls
try
{
    var response = await httpClient.GetAsync("/api/data");
    if (response.StatusCode == HttpStatusCode.Unauthorized)
    {
        // Token refresh failed, trigger re-authentication
        // This would typically be handled by the Blazor component
    }
}
catch (HttpRequestException ex)
{
    // Handle other HTTP errors
}
```

## Configuration

No additional configuration is required. The system uses the existing authentication configuration from `appsettings.json`:

```json
{
  "Authentication": {
    "Authority": "https://localhost:7113/",
    "ClientId": "mrwho_admin_web",
    "ClientSecret": "MrWhoAdmin2024!SecretKey"
  }
}
```

## Error Handling

### Common Scenarios:

1. **Refresh Token Expired**: User is automatically redirected to login
2. **No Refresh Token**: User is redirected to login 
3. **Network Issues**: Error is logged, user may need manual refresh
4. **Invalid Client Credentials**: Error is logged, admin intervention required

### Error Messages:

The system provides user-friendly error messages via:
- URL parameters (`?authError=true`, `?refreshError=true`)
- `AuthErrorNotification` component
- `BlazorAuthService.GetAuthenticationErrorMessage()`

## Logging

The system provides comprehensive logging for troubleshooting:

- Token refresh attempts and results
- Re-authentication triggers
- Error conditions and reasons
- API call authentication status

Log levels:
- `Debug`: Normal token operations
- `Information`: Successful refreshes and re-authentication
- `Warning`: Token expiry, refresh failures requiring re-auth
- `Error`: Unexpected exceptions

## Testing

To test the re-authentication flow:

1. **Simulate expired refresh token**: Manually corrupt the refresh token in browser cookies
2. **Wait for natural expiry**: Let tokens expire naturally (shorter expiry times in development)
3. **Use debug endpoints**: Use `/identity/token-inspector` to inspect token status

## Troubleshooting

### Common Issues:

1. **Infinite redirect loops**: Check that return URLs are properly encoded
2. **CORS issues**: Ensure authentication endpoints allow proper origins  
3. **Cookie issues**: Verify cookie settings in authentication configuration
4. **Blazor SignalR conflicts**: Middleware skips Blazor SignalR requests to avoid conflicts

### Debug Steps:

1. Check logs for token refresh attempts
2. Use `/auth/status` endpoint to check authentication state
3. Verify authentication configuration
4. Check browser network tab for authentication flows
5. Use `/identity/token-inspector` to examine tokens

## Security Considerations

- Automatic re-authentication maintains security by clearing expired credentials
- Users are always redirected through the official OIDC flow
- No sensitive information is logged
- Return URLs are validated to prevent open redirects
- Token rotation is properly handled when supported by the OIDC provider