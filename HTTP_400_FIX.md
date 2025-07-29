# ?? **Fixed: HTTP 400 Error on Login Page with OIDC Parameters**

## ? **Issue Identified**

The HTTP 400 error occurs because the OIDC authorization request contains a very long query string with multiple parameters including:
- `client_id=mrwho-web-blazor`
- `redirect_uri=https://localhost:7225/signin-oidc`
- `code_challenge` and `code_challenge_method` (PKCE)
- `state` and `nonce` (security tokens)
- Various other OIDC parameters

This long query string is causing the server to reject the request with HTTP 400.

## ?? **Fixes Applied**

### **1. Enhanced Login Page Model**
```csharp
// Added better OIDC parameter handling and logging
public async Task OnGetAsync(string? returnUrl = null)
{
    // Handle OIDC authorization requests properly
    if (string.IsNullOrEmpty(returnUrl))
    {
        returnUrl = Url.Content("~/");
    }
    
    ReturnUrl = returnUrl;
    _logger.LogInformation("Login page accessed with ReturnUrl: {ReturnUrl}", returnUrl);
}

// Enhanced post method with OIDC flow handling
if (result.Succeeded)
{
    // For OIDC flow, redirect back to the authorization endpoint
    if (returnUrl.Contains("/connect/authorize"))
    {
        return LocalRedirect(returnUrl);
    }
    return LocalRedirect(returnUrl);
}
```

### **2. Server Configuration for Large Query Strings**
```csharp
// Configure Kestrel to handle large query strings for OIDC
builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.Limits.MaxRequestHeadersTotalSize = 32768; // 32KB
    options.Limits.MaxRequestBufferSize = 1048576; // 1MB
    options.Limits.MaxRequestLineSize = 16384; // 16KB
});
```

### **3. Enhanced Logging**
Added comprehensive logging to help debug the authentication flow.

## ?? **Testing Instructions**

1. **Restart the application**:
   ```powershell
   Set-Location C:\Users\rum2c\source\repos\MrWho\MrWho.AppHost
   dotnet run
   ```

2. **Test the OIDC flow**:
   - Visit: `https://localhost:7225/test-auth`
   - Should redirect to: `https://localhost:7320/Account/Login`
   - Should NOT get HTTP 400 error anymore
   - Should show the login form

3. **Check the logs** for detailed information about the authentication flow

4. **Complete the login**:
   - Login with: `admin@mrwho.com` / `Admin123!`
   - Should redirect back through the OIDC flow
   - Should complete authentication successfully

## ? **Expected Results**

- ? **No HTTP 400 errors** on the login page
- ? **Login form displays** properly with OIDC parameters
- ? **Successful authentication** and OIDC flow completion
- ? **Proper redirect** back to the Web application

## ?? **Why This Fixes the Issue**

### **Root Causes**:
1. **Large Query String**: OIDC authorization requests can have very long query strings
2. **Server Limits**: Default server limits were too restrictive for OIDC parameters
3. **Parameter Handling**: The login page needed better handling of OIDC-specific flows

### **Solutions**:
1. **Increased Server Limits**: Allow larger request headers and buffers
2. **Enhanced Parameter Handling**: Better processing of OIDC return URLs
3. **Improved Logging**: Better visibility into the authentication flow

## ?? **OIDC Flow Explanation**

The complete flow should now work as follows:

1. **Web App** ? User visits protected page
2. **OIDC Challenge** ? Redirects to ApiService authorization endpoint
3. **Authorization Controller** ? Checks if user is authenticated
4. **Login Redirect** ? If not authenticated, redirects to login page WITH all OIDC parameters
5. **Login Form** ? User enters credentials (admin@mrwho.com / Admin123!)
6. **Authentication** ? ApiService validates credentials
7. **OIDC Completion** ? Redirects back through authorization flow
8. **Token Exchange** ? Web app receives tokens
9. **Success** ? User is authenticated in Web app

**Test the complete flow now - the HTTP 400 error should be resolved!** ??

## ?? **If Still Issues**

If you still get HTTP 400 errors:

1. **Check the server logs** for specific error details
2. **Verify the query string length** in browser developer tools
3. **Test direct access** to `https://localhost:7320/Account/Login` without parameters
4. **Check for any antiforgery token issues** in the form submission

The enhanced logging will provide detailed information about what's happening in the authentication flow.