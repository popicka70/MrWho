# ?? **FIXED: Added Port 7225 to Redirect URIs**

## ? **Issue Resolved**

Your Web application is running on port **7225**, which wasn't included in the OIDC client redirect URIs. I've now added it to the configuration.

## ?? **Change Made**

Added these specific redirect URIs to the `mrwho-web-blazor` client:
```csharp
// Added for your Web app running on port 7225
new Uri("https://localhost:7225/signin-oidc"),
new Uri("http://localhost:7225/signin-oidc"),
new Uri("https://localhost:7225/signout-callback-oidc"),
new Uri("http://localhost:7225/signout-callback-oidc")
```

## ?? **Testing Instructions**

1. **Restart the application** to apply the new client registration:
   ```powershell
   Set-Location C:\Users\rum2c\source\repos\MrWho\MrWho.AppHost
   dotnet run
   ```

2. **Look for this log** during startup:
   ```
   info: Updating existing Blazor Web application OIDC client with more redirect URIs...
   info: Blazor Web application OIDC client created successfully.
   ```

3. **Test the authentication flow**:
   - Visit: `https://localhost:7225/test-auth`
   - Should NOT get redirect URI error anymore
   - Should redirect to ApiService login page on port 7320
   - Login with `admin@mrwho.com` / `Admin123!`
   - Should redirect back to `https://localhost:7225` successfully

## ? **Expected Result**

No more `error:invalid_request` about redirect_uri. The authentication flow should now work end-to-end!

**Test it now and let me know how it goes!** ??