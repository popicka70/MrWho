# OIDC Web Flow Implementation Guide

## ?? **MrWho OIDC Provider - Web Flow Ready!**

Your MrWho identity provider now supports the complete OIDC authorization code flow for web applications and SPAs.

### **?? Available Endpoints**

| Endpoint | URL | Purpose |
|----------|-----|---------|
| **Authorization** | `/connect/authorize` | Initiate authentication flow |
| **Token** | `/connect/token` | Exchange authorization code for tokens |
| **Login** | `/Account/Login` | User login page |
| **Logout** | `/Account/Logout` | User logout page |

### **?? Pre-configured OIDC Clients**

#### **1. Server-to-Server Client**
```
Client ID: mrwho-client
Client Secret: mrwho-secret
Grant Types: password, client_credentials
```

#### **2. Web Application Client**
```
Client ID: mrwho-web-client  
Client Secret: mrwho-web-secret
Grant Types: authorization_code
Redirect URIs: 
  - https://localhost:5000/signin-oidc
  - https://localhost:5001/signin-oidc
Post-Logout URIs:
  - https://localhost:5000/signout-oidc
  - https://localhost:5001/signout-oidc
```

#### **3. SPA/Mobile Client**
```
Client ID: mrwho-spa-client
Grant Types: authorization_code (PKCE)
Redirect URIs:
  - https://localhost:3000/callback
  - https://localhost:4200/callback
```

### **?? OIDC Discovery Document**

Your OIDC provider exposes discovery metadata at:
```
https://localhost:7153/.well-known/openid_configuration
```

### **?? Integration Examples**

## **.NET Web Application Example**

```csharp
// Startup.cs or Program.cs
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = "oidc";
})
.AddCookie("Cookies")
.AddOpenIdConnect("oidc", options =>
{
    options.Authority = "https://localhost:7153";
    options.ClientId = "mrwho-web-client";
    options.ClientSecret = "mrwho-web-secret";
    options.ResponseType = "code";
    
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    
    options.GetClaimsFromUserInfoEndpoint = true;
    options.SaveTokens = true;
    
    // For development only
    options.RequireHttpsMetadata = false;
});

// In your controller
[Authorize]
public class SecureController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
```

## **React/JavaScript SPA Example**

```javascript
// Install: npm install oidc-client-ts

import { UserManager, UserManagerSettings } from 'oidc-client-ts';

const settings: UserManagerSettings = {
    authority: 'https://localhost:7153',
    client_id: 'mrwho-spa-client',
    redirect_uri: 'https://localhost:3000/callback',
    post_logout_redirect_uri: 'https://localhost:3000/',
    response_type: 'code',
    scope: 'openid profile email',
    automaticSilentRenew: true,
    silent_redirect_uri: 'https://localhost:3000/silent-callback'
};

const userManager = new UserManager(settings);

// Login
export const login = () => {
    return userManager.signinRedirect();
};

// Logout
export const logout = () => {
    return userManager.signoutRedirect();
};

// Get user info
export const getUser = () => {
    return userManager.getUser();
};
```

## **PowerShell Testing Script**

```powershell
# Test Authorization Code Flow
$clientId = "mrwho-web-client"
$redirectUri = "https://localhost:5001/signin-oidc"
$authority = "https://localhost:7153"

# Step 1: Build authorization URL
$authUrl = "$authority/connect/authorize?client_id=$clientId&redirect_uri=$redirectUri&response_type=code&scope=openid profile email"

Write-Host "Visit this URL to authenticate:" -ForegroundColor Green
Write-Host $authUrl

# Step 2: After user authentication, you'll receive an authorization code
# Use it to get tokens:
$code = "YOUR_AUTHORIZATION_CODE_HERE"
$tokenUrl = "$authority/connect/token"

$body = @{
    client_id = $clientId
    client_secret = "mrwho-web-secret"  
    grant_type = "authorization_code"
    code = $code
    redirect_uri = $redirectUri
}

$response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
$accessToken = $response.access_token

Write-Host "Access Token: $accessToken" -ForegroundColor Yellow
```

### **?? Testing the Web Flow**

1. **Start your MrWho services**:
```powershell
Set-Location MrWho.AppHost
dotnet run
```

2. **Test authorization endpoint**:
```
https://localhost:7153/connect/authorize?client_id=mrwho-web-client&redirect_uri=https://localhost:5001/signin-oidc&response_type=code&scope=openid%20profile%20email
```

3. **Login with test user**:
```
Email: admin@mrwho.com
Password: Admin123!
```

### **?? Available Scopes**

- **`openid`**: Basic OpenID Connect identity
- **`profile`**: User profile information (name, username)  
- **`email`**: User email address and verification status
- **`roles`**: User roles and permissions

### **?? Claims Provided**

| Claim | Description | Scope Required |
|-------|-------------|----------------|
| `sub` | User ID | Always |
| `preferred_username` | Username | Always |
| `email` | Email address | email |
| `email_verified` | Email verification status | email |
| `given_name` | First name | profile |
| `family_name` | Last name | profile |
| `name` | Full name | profile |
| `role` | User role | roles |

### **?? Security Notes**

1. **Development Certificates**: Currently using development certificates - replace with real certificates in production
2. **HTTP vs HTTPS**: Configure proper HTTPS in production
3. **Client Secrets**: Store client secrets securely (Azure Key Vault, etc.)
4. **Redirect URIs**: Validate redirect URIs strictly in production
5. **CORS**: Configure CORS policies for SPA applications

### **?? Next Steps**

1. **Create your client application** using one of the examples above
2. **Test the authentication flow** with the provided test user
3. **Customize the login page** styling in `Pages/Account/Login.cshtml`
4. **Add more OIDC clients** by modifying the seeding in `Program.cs`
5. **Implement consent screens** for third-party applications (optional)

Your MrWho OIDC provider is now ready to authenticate users for external applications! ??