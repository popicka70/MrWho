# Infinite Login Loop Troubleshooting Guide

## Problem Description

You're experiencing an endless login loop where users get redirected to login, authenticate successfully, but then get redirected back to login again indefinitely.

## Root Cause Analysis

Based on your code structure, the infinite loop is likely caused by one or more of these issues:

### 1. **Redirect URI Mismatch**
The most common cause is a mismatch between configured redirect URIs in your OIDC client and what your application is actually using.

### 2. **Authentication State Not Being Preserved**
The authentication cookies aren't being properly set or are being cleared immediately after login.

### 3. **Middleware Order Issues**
Authentication middleware might not be in the correct order or configured properly.

### 4. **Cookie Configuration Problems**
Cookie settings (SameSite, Secure, Domain) might be preventing proper authentication state storage.

## Diagnostic Steps

### Step 1: Check Client Configuration

First, verify your OIDC client configuration in the database:

```bash
# Navigate to MrWho OIDC server URL
https://localhost:7113/debug/admin-client-info
```

This should show:
- `ClientId`: `mrwho_admin_web`
- `RedirectUris`: Should include `https://localhost:7257/signin-oidc`
- `PostLogoutRedirectUris`: Should include `https://localhost:7257/signout-callback-oidc`

### Step 2: Clear Authentication State

Use the debug endpoint I added to clear all authentication state:

```bash
# Navigate to (development only)
https://localhost:7257/debug/clear-auth
```

### Step 3: Check Browser Network Tab

1. Open browser DevTools ? Network tab
2. Try to access a protected page
3. Watch for redirect patterns:
   - `/login` ? OIDC provider ? `/signin-oidc` ? protected page ? (correct)
   - `/login` ? OIDC provider ? `/signin-oidc` ? `/login` ? ... ? (loop)

### Step 4: Check Console Logs

Look for these authentication events in your application logs:
- "Redirecting to identity provider"
- "Token validated successfully"  
- "Authentication failed" or "Remote authentication failure"

## Immediate Fixes to Try

### Fix 1: Update Cookie Configuration

Add this to your `ServiceCollectionExtensions.cs` in the authentication configuration:

```csharp
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/login";
    options.LogoutPath = "/logout";
    options.AccessDeniedPath = "/access-denied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    
    // Critical for development with HTTPS
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.HttpOnly = true;
})
```

### Fix 2: Ensure Proper Redirect URI Registration

Run this PowerShell script to verify/fix redirect URIs:

```powershell
# Check if the admin client has correct redirect URIs
$response = Invoke-WebRequest -Uri "https://localhost:7113/debug/admin-client-info" -UseBasicParsing
$clientInfo = $response.Content | ConvertFrom-Json

Write-Host "Current Redirect URIs:"
$clientInfo.RedirectUris

# Should include: https://localhost:7257/signin-oidc
```

### Fix 3: Simplify Login Endpoint

Update your login endpoint in `WebApplicationExtensions.cs`:

```csharp
app.MapGet("/login", async (HttpContext context, string? returnUrl = null) =>
{
    // Validate return URL to prevent open redirects
    if (!string.IsNullOrEmpty(returnUrl) && !returnUrl.StartsWith("/"))
    {
        returnUrl = "/";
    }

    var properties = new AuthenticationProperties
    {
        RedirectUri = returnUrl ?? "/",
        IsPersistent = false
    };

    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
});
```

## Advanced Debugging

### Enable Detailed Authentication Logging

Add this to your `appsettings.Development.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore.Authentication": "Debug",
      "Microsoft.AspNetCore.Authorization": "Debug",
      "Microsoft.AspNetCore.Authentication.OpenIdConnect": "Debug",
      "Microsoft.AspNetCore.Authentication.Cookies": "Debug"
    }
  }
}
```

### Check Token Inspector

Use the Token Inspector to examine authentication state:

1. Navigate to: `https://localhost:7113/identity/token-inspector`
2. If you can access it, check the "Current" endpoint: `https://localhost:7113/identity/token-inspector/current`

### Verify OIDC Discovery Document

Check the OpenID Connect configuration:

```bash
https://localhost:7113/.well-known/openid_configuration
```

Verify these endpoints are correct:
- `authorization_endpoint`: `https://localhost:7113/connect/authorize`
- `token_endpoint`: `https://localhost:7113/connect/token`
- `end_session_endpoint`: `https://localhost:7113/connect/logout`

## Testing the Fix

### Test Sequence

1. **Clear all browser data** (cookies, cache, local storage)
2. **Navigate to**: `https://localhost:7257/debug/clear-auth`
3. **Navigate to**: `https://localhost:7257/`
4. **Click on a protected link** (e.g., "Realms" in navigation)
5. **Should redirect to**: `https://localhost:7113/connect/login`
6. **Login with**: `admin@mrwho.local` / `MrWhoAdmin2024!`
7. **Should redirect back to**: `https://localhost:7257/realms`

### Success Indicators

- ? No infinite redirects
- ? Can access protected pages after login
- ? Authentication state persists across page refreshes
- ? Logout works properly

## Common Issues and Solutions

### Issue: "OIDC callback endpoint should not be called directly"

**Cause**: Direct navigation to `/signin-oidc`
**Solution**: This is normal behavior, indicates the endpoint is working

### Issue: "Authentication failed" in logs

**Cause**: Usually redirect URI mismatch or client configuration issues
**Solution**: Verify client configuration using `/debug/admin-client-info`

### Issue: Cookies not being set

**Cause**: Cookie security settings or SameSite policies
**Solution**: Update cookie configuration as shown in Fix 1

### Issue: Token refresh errors

**Cause**: Invalid refresh tokens or misconfigured token refresh service
**Solution**: The new token refresh implementation should handle this automatically

## Emergency Reset Procedure

If nothing else works, follow this complete reset procedure:

1. **Stop both applications**
2. **Clear browser data completely**
3. **Delete database** (development only):
   ```powershell
   # If using LocalDB
   SqlLocalDB stop MSSQLLocalDB
   SqlLocalDB delete MSSQLLocalDB
   SqlLocalDB create MSSQLLocalDB
   ```
4. **Start MrWho OIDC server**: `dotnet run` in MrWho directory
5. **Wait for "Essential data created"** message
6. **Start MrWhoAdmin.Web**: `dotnet run` in MrWhoAdmin.Web directory
7. **Test authentication flow**

## Verification Commands

Use these PowerShell commands to verify your setup:

```powershell
# Test OIDC discovery
$discovery = Invoke-WebRequest "https://localhost:7113/.well-known/openid_configuration" | ConvertFrom-Json
Write-Host "Authorization Endpoint: $($discovery.authorization_endpoint)"

# Test admin client info
$client = Invoke-WebRequest "https://localhost:7113/debug/admin-client-info" | ConvertFrom-Json
Write-Host "Client ID: $($client.ClientId)"
Write-Host "Redirect URIs: $($client.RedirectUris -join ', ')"

# Test admin web accessibility
try {
    $response = Invoke-WebRequest "https://localhost:7257/" -UseBasicParsing
    Write-Host "Admin Web Status: $($response.StatusCode)"
} catch {
    Write-Host "Admin Web Error: $($_.Exception.Message)"
}
```

## Contact Points

If the issue persists after trying these solutions:

1. Check the comprehensive logs with debug-level authentication logging enabled
2. Compare your network traffic with the expected flow shown above
3. Verify that both applications are running on the correct ports (7113 for OIDC server, 7257 for admin web)
4. Ensure no firewall or proxy is interfering with the authentication flow

The enhanced authentication system I implemented should prevent most infinite loop scenarios through:
- Better error handling and redirects
- Comprehensive logging
- Proper callback path handling
- Authentication state validation
- Automatic re-authentication when needed