# Identity Resources and ID Token Claims

This document explains how identity resources are automatically attached to ID tokens through the UserInfo endpoint in the MrWho OpenIddict implementation.

## How It Works

### 1. Identity Resource Configuration

Identity resources define which claims should be included in the UserInfo response based on the requested scopes. Each identity resource has:

- **Name**: The scope name that triggers this resource (e.g., "profile", "email", "custom_claims")
- **User Claims**: List of claim types to include when this scope is requested
- **Properties**: Optional metadata

### 2. Enhanced UserInfo Endpoint

The `UserInfoHandler` has been enhanced to:

1. **Extract scopes** from the access token
2. **Load identity resources** that match the requested scopes
3. **Build claims dynamically** based on the identity resource configuration
4. **Return claims** in the UserInfo response

### 3. Claims Mapping

The enhanced UserInfo handler supports these claim types:

#### Standard OpenID Connect Claims
- `sub` - Subject identifier (user ID)
- `email` - User's email address
- `email_verified` - Email verification status
- `name` - User's display name
- `preferred_username` - Preferred username
- `phone_number` - Phone number
- `phone_number_verified` - Phone verification status

#### Role Claims
- `role` - User roles (returned as array)

#### Custom Claims
- Any custom claim stored in the user's claims collection

## Example: Custom Identity Resource

### 1. Create a Custom Identity Resource

```csharp
// In the Admin Web interface or via API
var customIdentityResource = new CreateIdentityResourceRequest
{
    Name = "custom_profile",
    DisplayName = "Custom Profile Information",
    Description = "Extended profile claims including department and title",
    IsEnabled = true,
    ShowInDiscoveryDocument = true,
    UserClaims = new List<string>
    {
        "department",
        "job_title",
        "employee_id",
        "manager_email"
    }
};
```

### 2. Add Custom Claims to Users

```csharp
// Add custom claims to a user
await userManager.AddClaimAsync(user, new Claim("department", "Engineering"));
await userManager.AddClaimAsync(user, new Claim("job_title", "Senior Developer"));
await userManager.AddClaimAsync(user, new Claim("employee_id", "EMP001"));
await userManager.AddClaimAsync(user, new Claim("manager_email", "manager@company.com"));
```

### 3. Request Token with Custom Scope

```bash
curl -X POST https://localhost:7113/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=postman_client" \
  -d "client_secret=postman_secret" \
  -d "username=user@example.com" \
  -d "password=Password123!" \
  -d "scope=openid email profile custom_profile"
```

### 4. Call UserInfo Endpoint

```bash
curl -X GET https://localhost:7113/connect/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Expected UserInfo Response

```json
{
  "sub": "user-id-12345",
  "email": "user@example.com",
  "email_verified": true,
  "name": "user@example.com",
  "preferred_username": "user@example.com",
  "department": "Engineering",
  "job_title": "Senior Developer",
  "employee_id": "EMP001",
  "manager_email": "manager@company.com"
}
```

## Benefits

### 1. Dynamic Configuration
- No code changes needed to add new claims
- Identity resources can be configured through the admin interface
- Claims are automatically included based on requested scopes

### 2. Scope-Based Access Control
- Only claims from requested scopes are returned
- Fine-grained control over which claims each client can access
- Follows OpenID Connect specification

### 3. Extensible
- Support for custom claim types
- Easy to add new standard claims
- Flexible claim value resolution

## Testing

### PowerShell Test Script

```powershell
# Get access token with multiple scopes
$tokenResponse = Invoke-RestMethod -Uri "https://localhost:7113/connect/token" -Method POST -ContentType "application/x-www-form-urlencoded" -Body @{
    grant_type = "password"
    client_id = "postman_client"
    client_secret = "postman_secret"
    username = "test@example.com"
    password = "Test123!"
    scope = "openid profile email roles custom_profile"
}

# Call UserInfo endpoint
$userInfo = Invoke-RestMethod -Uri "https://localhost:7113/connect/userinfo" -Method GET -Headers @{
    Authorization = "Bearer $($tokenResponse.access_token)"
}

# Display result
$userInfo | ConvertTo-Json -Depth 3
```

### C# Integration Test

```csharp
[Fact]
public async Task UserInfo_WithCustomIdentityResource_ReturnsCustomClaims()
{
    // Arrange: Create identity resource and user with custom claims
    var customResource = CreateCustomIdentityResource();
    var user = CreateUserWithCustomClaims();
    
    // Act: Get token and call UserInfo
    var token = await GetAccessTokenAsync("openid custom_profile");
    var userInfo = await CallUserInfoEndpointAsync(token);
    
    // Assert: Verify custom claims are present
    Assert.Contains("department", userInfo);
    Assert.Contains("job_title", userInfo);
}
```

## Administrative Interface

The identity resources can be managed through the admin web interface:

1. **Navigate to Identity Resources** in the admin panel
2. **Create or Edit** identity resources
3. **Add User Claims** to define which claims to include
4. **Enable/Disable** resources as needed
5. **Configure Properties** for additional metadata

The changes take effect immediately without requiring application restart.