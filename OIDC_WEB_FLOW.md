# OIDC Web Flow Implementation Guide

## ?? **MrWho OIDC Provider - Complete Well-Known Endpoints**

Your MrWho identity provider now supports the complete OIDC specification with all standard well-known endpoints, just like Keycloak!

### **?? Standard OIDC Well-Known Endpoints**

| Endpoint | URL | Purpose |
|----------|-----|---------|
| **Discovery Document** | `/.well-known/openid_configuration` | OIDC discovery metadata (auto-generated) |
| **JWKS** | `/.well-known/jwks` | JSON Web Key Set for token verification |
| **Endpoints Info** | `/.well-known/endpoints` | Custom endpoint showing all available endpoints |

### **?? OIDC Protocol Endpoints**

| Endpoint | URL | Purpose |
|----------|-----|---------|
| **Authorization** | `/connect/authorize` | Initiate authentication flow |
| **Token** | `/connect/token` | Exchange authorization code for tokens |
| **UserInfo** | `/connect/userinfo` | Get user information with access token |
| **Introspection** | `/connect/introspect` | Validate and inspect tokens |
| **Revocation** | `/connect/revoke` | Revoke access/refresh tokens |

### **?? User Authentication Endpoints**

| Endpoint | URL | Purpose |
|----------|-----|---------|
| **Login** | `/Account/Login` | User login page |
| **Logout** | `/Account/Logout` | User logout page |

### **??? Discovery Document Example**

Your OIDC discovery document is available at:
```
https://localhost:7153/.well-known/openid_configuration
```

Example response:
```json
{
  "issuer": "https://localhost:7153",
  "authorization_endpoint": "https://localhost:7153/connect/authorize",
  "token_endpoint": "https://localhost:7153/connect/token",
  "userinfo_endpoint": "https://localhost:7153/connect/userinfo",
  "jwks_uri": "https://localhost:7153/.well-known/jwks",
  "scopes_supported": ["openid", "profile", "email", "roles"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "password", "client_credentials", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

### **?? Test the Well-Known Endpoints**

```powershell
# Get discovery document (like Keycloak's)
Invoke-RestMethod -Uri "https://localhost:7153/.well-known/openid_configuration"

# Get JWKS for token verification
Invoke-RestMethod -Uri "https://localhost:7153/.well-known/jwks"

# Get custom endpoints information
Invoke-RestMethod -Uri "https://localhost:7153/.well-known/endpoints"
```

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
    // Use discovery document (like Keycloak)
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
    // Authority will automatically discover endpoints
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

// Get user info (using userinfo endpoint)
export const getUser = () => {
    return userManager.getUser();
};
```

## **Keycloak-style Configuration (Drop-in Replacement)**

If migrating from Keycloak, you can use MrWho as a drop-in replacement:

```yaml
# Docker Compose or Kubernetes
services:
  identity:
    # Change from Keycloak to MrWho
    image: mrwho:latest
    environment:
      - OIDC_ISSUER=https://localhost:7153
    ports:
      - "7153:80"
```

```json
# Client configuration (same as Keycloak)
{
  "issuer": "https://localhost:7153",
  "auth-server-url": "https://localhost:7153",
  "realm": "mrwho",
  "client-id": "mrwho-web-client",
  "credentials": {
    "secret": "mrwho-web-secret"
  }
}
```

### **?? Available Scopes & Claims**

| Scope | Claims Included | Description |
|-------|----------------|-------------|
| **`openid`** | `sub` | OpenID Connect identity |
| **`profile`** | `name`, `given_name`, `family_name`, `preferred_username` | User profile information |
| **`email`** | `email`, `email_verified` | Email address and verification |
| **`roles`** | `role` | User roles and permissions |

### **?? Testing with Standard OIDC Tools**

#### **Postman Collection Example**
```json
{
  "auth": {
    "type": "oauth2",
    "oauth2": [
      {
        "key": "authUrl",
        "value": "https://localhost:7153/connect/authorize"
      },
      {
        "key": "accessTokenUrl", 
        "value": "https://localhost:7153/connect/token"
      },
      {
        "key": "clientId",
        "value": "mrwho-web-client"
      },
      {
        "key": "clientSecret",
        "value": "mrwho-web-secret"
      }
    ]
  }
}
```

#### **OIDC Debugger Tool**
Visit https://oidcdebugger.com/ and use:
- **Discovery Document URL**: `https://localhost:7153/.well-known/openid_configuration`
- **Client ID**: `mrwho-spa-client`
- **Redirect URI**: `https://oidcdebugger.com/debug`

### **? Performance & Standards**

- ? **OpenID Connect 1.0** compliant
- ? **OAuth 2.0** RFC 6749 compliant  
- ? **JWT tokens** with RS256 signing
- ? **Discovery document** auto-generation
- ? **JWKS endpoint** for key rotation
- ? **Standard error responses** (RFC 6749)
- ? **CORS support** for SPA applications

### **?? Migration from Keycloak**

MrWho provides the same well-known endpoints as Keycloak:

| Keycloak Endpoint | MrWho Equivalent | Status |
|-------------------|------------------|---------|
| `/auth/realms/master/.well-known/openid_configuration` | `/.well-known/openid_configuration` | ? Compatible |
| `/auth/realms/master/protocol/openid-connect/certs` | `/.well-known/jwks` | ? Compatible |
| `/auth/realms/master/protocol/openid-connect/auth` | `/connect/authorize` | ? Compatible |
| `/auth/realms/master/protocol/openid-connect/token` | `/connect/token` | ? Compatible |
| `/auth/realms/master/protocol/openid-connect/userinfo` | `/connect/userinfo` | ? Compatible |

### **?? Security Notes**

1. **HTTPS in Production**: Enable HTTPS with real certificates
2. **Client Secrets**: Store securely (Azure Key Vault, etc.)
3. **JWKS Rotation**: Consider implementing key rotation for production
4. **Rate Limiting**: Implement rate limiting on authentication endpoints
5. **CORS Configuration**: Configure CORS policies for SPA applications

### **?? Next Steps**

1. **Test Discovery**: Visit `/.well-known/openid_configuration`
2. **Verify JWKS**: Check `/.well-known/jwks` for public keys
3. **Create Client App**: Use standard OIDC libraries
4. **Test Authentication**: Use provided test credentials
5. **Monitor Logs**: Check application logs for OIDC flows

Your MrWho OIDC provider now provides **complete Keycloak-compatible well-known endpoints**! ??