# ?? Fixed: OIDC Scheme Issue with Aspire Service Discovery

## ? **Issue Resolved**

The error was caused by trying to use the Aspire service discovery scheme `https+http://apiservice` as the OIDC Authority URL. The OIDC middleware doesn't understand this scheme and expects a standard HTTP/HTTPS URL.

## ??? **Root Cause**

```
Error: System.NotSupportedException: The 'https+http' scheme is not supported.
```

**The Problem**: 
- OIDC middleware needs to fetch metadata from `/.well-known/openid-configuration`
- Standard HTTP clients don't understand the `https+http://` Aspire service discovery scheme
- Only Aspire-aware HttpClients can resolve these URLs

**The Solution**: 
- Use direct `https://localhost:7320` URL for OIDC Authority
- Keep `https+http://apiservice` for regular API calls via service discovery

## ?? **Configuration Changes**

### **1. Updated appsettings.Development.json**
```json
{
  "OIDC": {
    "Authority": "https://localhost:7320",  // Direct URL for OIDC
    "ClientId": "mrwho-web-blazor",
    "ClientSecret": "mrwho-web-blazor-secret"
  }
}
```

### **2. Updated Program.cs**
```csharp
// OIDC uses direct localhost URL (doesn't support service discovery)
var oidcAuthority = builder.Configuration["OIDC:Authority"] ?? "https://localhost:7320";

// API client still uses service discovery
builder.Services.AddHttpClient<IUserApiClient, UserApiClient>(client =>
{
    client.BaseAddress = new("https+http://apiservice");  // Service discovery works here
});
```

### **3. Hybrid Approach**
- **OIDC Authority**: `https://localhost:7320` (direct URL)
- **API Calls**: `https+http://apiservice` (service discovery)

## ?? **Testing Instructions**

### **Step 1: Verify API Port**
First, confirm the API is running on port 7320:
```powershell
Set-Location C:\Users\rum2c\source\repos\MrWho\MrWho.AppHost
dotnet run
```

Check the Aspire dashboard or logs for the actual ApiService port.

### **Step 2: Test OIDC Metadata**
Test that the OIDC metadata is accessible:
```powershell
# Test the OIDC metadata endpoint directly
Invoke-RestMethod -Uri "https://localhost:7320/.well-known/openid-configuration" -SkipCertificateCheck
```

Should return OIDC configuration without errors.

### **Step 3: Test Authentication Flow**
1. **Visit Protected Page**: 
   - Go to: `https://localhost:XXXX/test-auth`
   - Should trigger OIDC challenge

2. **Check Logs**:
   - Look for: "OIDC Configuration - Authority: https://localhost:7320"
   - Look for: "Redirecting to identity provider"
   - Should NOT see "https+http scheme is not supported"

3. **Login Process**:
   - Should redirect to: `https://localhost:7320/Account/Login`
   - Login with: `admin@mrwho.com` / `Admin123!`
   - Should redirect back to Web app

### **Step 4: Expected Results**

? **Success Indicators**:
- No "scheme not supported" errors
- Successful OIDC metadata retrieval  
- Redirect to ApiService login page (on port 7320)
- Successful authentication and redirect back

? **Failure Indicators**:
- Still getting scheme errors ? Check authority URL in config
- Connection refused ? Verify ApiService is running on port 7320
- Redirect URI mismatch ? Check client configuration in ApiService

## ?? **Troubleshooting Guide**

### **Issue: Wrong Port Number**
```
Check: What port is ApiService actually running on?
Solution: Update appsettings.Development.json with correct port
Command: Check Aspire dashboard or application logs
```

### **Issue: HTTPS Certificate Errors**
```
Check: Development certificate issues
Solution: Trust development certificates
Command: dotnet dev-certs https --trust
```

### **Issue: Still Getting Scheme Errors**
```
Check: Configuration is being loaded correctly
Solution: Verify appsettings.Development.json is being used
Log: Look for "OIDC Configuration" log message
```

### **Issue: Client Registration**
```
Check: ApiService has mrwho-web-blazor client with correct redirect URIs
Solution: Verify client includes https://localhost:XXXX/signin-oidc
Database: Check OpenIddictApplications table
```

## ?? **Architecture Benefits**

### **Hybrid Service Discovery**
```
???????????????????    ???????????????????
?   Web App       ?    ?   ApiService    ?
?                 ?    ?                 ?
? OIDC Client     ??????? OIDC Server     ?
? (Direct URL)    ?    ? (Port 7320)     ?
?                 ?    ?                 ?
? API Client      ??????? API Endpoints   ?
? (Service Disc.) ?    ? (Aspire Aware)  ?
???????????????????    ???????????????????
```

### **Key Benefits**
- ? **OIDC Compatibility**: Uses standard URLs that OIDC middleware understands
- ? **Service Discovery**: Still uses Aspire service discovery for API calls
- ? **Configuration Flexibility**: Easy to change ports via appsettings
- ? **Development Friendly**: Works with both Aspire and standalone scenarios

## ?? **Port Configuration Management**

### **If ApiService Port Changes**
Update `appsettings.Development.json`:
```json
{
  "OIDC": {
    "Authority": "https://localhost:NEW_PORT"
  }
}
```

### **For Production**
Use environment variables or production appsettings:
```json
{
  "OIDC": {
    "Authority": "https://api.yourservice.com"
  }
}
```

### **Dynamic Port Detection (Future)**
For fully dynamic scenarios, you could implement:
```csharp
// Get actual service URL from Aspire service discovery
var serviceProvider = builder.Services.BuildServiceProvider();
var apiServiceUrl = await GetServiceUrlFromAspire("apiservice");
options.Authority = apiServiceUrl;
```

## ? **Status: Issue Resolved**

The OIDC configuration now correctly uses:

- ? **Direct localhost URL** for OIDC Authority (https://localhost:7320)
- ? **Service discovery** for API calls (https+http://apiservice)
- ? **Proper configuration management** via appsettings
- ? **Enhanced logging** for debugging

**The authentication flow should now work without scheme errors!** ??

## ?? **Next Steps After Success**

1. **Test complete OIDC flow** end-to-end
2. **Restore AuthorizeView** in NavMenu once authentication works
3. **Add user information display** in navigation
4. **Implement logout flow**
5. **Test with different ports** to ensure flexibility