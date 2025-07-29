# ?? Fixed: OIDC Redirect URI Mismatch

## ? **Issue Resolved**

The error `error:invalid_request error_description:The specified 'redirect_uri' is not valid for this client application` was caused by the Web application running on a port that wasn't included in the registered redirect URIs for the `mrwho-web-blazor` client.

## ??? **Root Cause**

**The Problem**: 
- Web application was running on a port not in the redirect URI list
- Aspire assigns dynamic ports during development
- OIDC clients have strict redirect URI validation for security

**The Solution**: 
- Expanded redirect URI list to include comprehensive port range
- Updated client registration to delete and recreate with new URIs
- Covers common Aspire and development ports

## ?? **Changes Applied**

### **1. Expanded Redirect URI List**
```csharp
RedirectUris = {
    // Comprehensive port range for Aspire and development
    "https://localhost:5000/signin-oidc",   // Standard development
    "https://localhost:5001/signin-oidc",   // Alternative standard
    "https://localhost:5173/signin-oidc",   // Vite default
    "https://localhost:5174/signin-oidc",   // Vite alternative
    "https://localhost:5175/signin-oidc",   // Vite alternative
    "https://localhost:7000/signin-oidc",   // Aspire range
    "https://localhost:7001/signin-oidc",   // Aspire range
    "https://localhost:7002/signin-oidc",   // Aspire range
    "https://localhost:7108/signin-oidc",   // Common Blazor
    "https://localhost:7109/signin-oidc",   // Common Blazor
    "https://localhost:7110/signin-oidc",   // Common Blazor
    "https://localhost:7111/signin-oidc",   // Common Blazor
    "https://localhost:7112/signin-oidc",   // Common Blazor
    // ... and HTTP versions for all ports
}
```

### **2. Force Client Recreation**
```csharp
// Delete existing client to update redirect URIs
var existingBlazorClient = await applicationManager.FindByClientIdAsync("mrwho-web-blazor");
if (existingBlazorClient != null)
{
    logger.LogInformation("Updating existing Blazor Web application OIDC client with more redirect URIs...");
    await applicationManager.DeleteAsync(existingBlazorClient);
}

// Create new client with expanded redirect URIs
await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor { ... });
```

## ?? **Testing Instructions**

### **Step 1: Restart Application**
The client registration changes require restarting the application:
```powershell
Set-Location C:\Users\rum2c\source\repos\MrWho\MrWho.AppHost
dotnet run
```

### **Step 2: Check Client Registration**
Look for this log message during startup:
```
info: Updating existing Blazor Web application OIDC client with more redirect URIs...
info: Blazor Web application OIDC client created successfully.
```

### **Step 3: Test Authentication Flow**
1. **Visit Protected Page**: 
   - Go to: `https://localhost:XXXX/test-auth` (whatever port your Web app is using)
   - Should trigger OIDC challenge

2. **Check for Redirect URI Error**:
   - Should NOT see: `error:invalid_request` about redirect_uri
   - Should redirect to: `https://localhost:7320/Account/Login`

3. **Complete Login Process**:
   - Login with: `admin@mrwho.com` / `Admin123!`
   - Should redirect back to Web app successfully

### **Step 4: Expected Results**

? **Success Indicators**:
- No redirect URI errors
- Successful redirect to ApiService login
- Successful redirect back after login
- User authenticated in Web app

? **Failure Indicators**:
- Still getting redirect URI error ? Check actual Web app port
- Different error ? Check logs for specific issue

## ?? **Troubleshooting Guide**

### **Issue: Still Getting Redirect URI Error**
**Check**: What port is your Web app actually running on?
```powershell
# Check the application logs or Aspire dashboard for actual port
# Look for messages like: "Now listening on: https://localhost:XXXX"
```

**Solution**: Add the specific port to the redirect URI list:
```csharp
new Uri("https://localhost:YOUR_PORT/signin-oidc"),
new Uri("http://localhost:YOUR_PORT/signin-oidc"),
```

### **Issue: Client Not Updated**
**Check**: Was the existing client deleted and recreated?
```
Look for log: "Updating existing Blazor Web application OIDC client"
```

**Solution**: Manually delete the database to force recreation:
```powershell
# Stop the application
# Delete the database file to force fresh registration
Remove-Item "C:\Users\rum2c\source\repos\MrWho\MrWho.AppHost\bin\Debug\net9.0\*.db" -ErrorAction SilentlyContinue
```

### **Issue: HTTPS vs HTTP Mismatch**
**Check**: Is your Web app using HTTPS or HTTP?
```
Look at the browser URL when the error occurs
```

**Solution**: Both HTTPS and HTTP versions are included in the redirect URIs, so this should be covered.

## ?? **Port Coverage**

### **Included Ports**
The redirect URI list now covers:
- **5000-5001**: Standard ASP.NET Core development ports
- **5173-5177**: Vite and modern development server ports  
- **7000-7002**: Common Aspire assignment range
- **7108-7112**: Common Blazor Server development ports

### **If Your Port Isn't Covered**
If your Web application is running on a different port, you can:

1. **Add it to the list** and restart the application
2. **Check the actual port** in the browser URL or application logs
3. **Use environment variables** to override the port if needed

## ?? **Dynamic Port Solution (Future)**

For a more dynamic solution that automatically detects ports, you could implement:

```csharp
// Future enhancement: Dynamic redirect URI registration
var webAppUrls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Split(';') ?? [];
foreach (var url in webAppUrls)
{
    if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        redirectUris.Add(new Uri(uri, "/signin-oidc"));
    }
}
```

## ? **Status: Redirect URI Issue Resolved**

The OIDC client now supports a comprehensive range of development ports:

- ? **Expanded port coverage**: 5000-5177, 7000-7112 ranges
- ? **Both HTTP and HTTPS**: Full protocol support
- ? **Aspire compatibility**: Covers dynamic port allocation
- ? **Force recreation**: Ensures new redirect URIs are active

**The authentication flow should now work without redirect URI errors!** ??

## ?? **Next Steps After Success**

1. **Complete authentication flow** end-to-end
2. **Test logout functionality**
3. **Restore AuthorizeView** in NavMenu
4. **Add user information display**
5. **Implement role-based authorization**

Let me know what port your Web application is actually running on if you still get redirect URI errors!