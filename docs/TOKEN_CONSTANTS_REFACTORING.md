# Token Constants Refactoring

## Overview

This document describes the refactoring of hardcoded token-related string literals into centralized constants in the shared library. This improves maintainability, reduces errors, and ensures consistency across the entire solution.

## Problem Solved

**Before**: Token-related strings were scattered throughout the codebase as magic strings:

```csharp
// ? Multiple hardcoded strings across different files
await httpContext.GetTokenAsync("access_token");
await httpContext.GetTokenAsync("refresh_token");
await httpContext.GetTokenAsync("expires_at");

var tokenRequest = new Dictionary<string, string>
{
    ["grant_type"] = "refresh_token",
    ["client_id"] = clientId,
    ["client_secret"] = clientSecret
};

[JsonPropertyName("access_token")]
public string? AccessToken { get; set; }
```

**After**: Centralized constants in the shared library:

```csharp
// ? Centralized constants from MrWho.Shared
await httpContext.GetTokenAsync(TokenConstants.TokenNames.AccessToken);
await httpContext.GetTokenAsync(TokenConstants.TokenNames.RefreshToken);
await httpContext.GetTokenAsync(TokenConstants.TokenNames.ExpiresAt);

var tokenRequest = new Dictionary<string, string>
{
    [TokenConstants.ParameterNames.GrantType] = TokenConstants.GrantTypes.RefreshToken,
    [TokenConstants.ParameterNames.ClientId] = clientId,
    [TokenConstants.ParameterNames.ClientSecret] = clientSecret
};

[JsonPropertyName(TokenConstants.JsonPropertyNames.AccessToken)]
public string? AccessToken { get; set; }
```

## Constants Structure

### `TokenConstants.TokenNames`
Used with `GetTokenAsync()` and `UpdateTokenValue()`:
- `AccessToken` = "access_token"
- `RefreshToken` = "refresh_token"
- `IdToken` = "id_token"
- `ExpiresAt` = "expires_at"
- `TokenType` = "token_type"

### `TokenConstants.ParameterNames`
Used in OAuth2/OIDC token requests:
- `GrantType` = "grant_type"
- `ClientId` = "client_id"
- `ClientSecret` = "client_secret"
- `RefreshToken` = "refresh_token"
- `Username` = "username"
- `Password` = "password"
- `Scope` = "scope"
- And more...

### `TokenConstants.GrantTypes`
OAuth2 grant type values:
- `AuthorizationCode` = "authorization_code"
- `ClientCredentials` = "client_credentials"
- `Password` = "password"
- `RefreshToken` = "refresh_token"
- And more...

### `TokenConstants.JsonPropertyNames`
For JSON serialization/deserialization:
- `AccessToken` = "access_token"
- `RefreshToken` = "refresh_token"
- `TokenType` = "token_type"
- `ExpiresIn` = "expires_in"
- And more...

### `TokenConstants.TokenTypes`
Common token type values:
- `Bearer` = "Bearer"
- `Mac` = "mac"
- `Pop` = "pop"

### `TokenConstants.ErrorCodes`
OAuth2 error codes:
- `InvalidGrant` = "invalid_grant"
- `InvalidClient` = "invalid_client"
- `InvalidRequest` = "invalid_request"
- And more...

## Updated Components

The following components have been updated to use the new constants:

### **Core Services**
- ? `TokenRefreshService.cs` - All token operations
- ? `AuthenticationDelegatingHandler.cs` - API request authentication
- ? `TokenRefreshMiddleware.cs` - Proactive token refresh

### **Controllers**
- ? `TokenController.cs` - Token status and refresh endpoints

### **UI Components**
- ? `DebugTokenRefresh.razor` - Debug page for token operations
- ? All debug and token-related Razor components

### **Configuration**
- ? `ServiceCollectionExtensions.cs` - OpenIddict scope configuration

## Benefits

### **1. Maintainability**
- **Single source of truth** for all token-related strings
- **Easy updates** - change once, apply everywhere
- **Reduced duplication** - no more scattered magic strings

### **2. Type Safety**
- **Compile-time checking** - typos caught at build time
- **IntelliSense support** - IDE autocomplete and refactoring
- **Refactoring safety** - IDE can rename across files

### **3. Consistency**
- **Standardized naming** across the entire solution
- **Clear organization** - related constants grouped together
- **Documentation** - constants include XML documentation

### **4. Error Prevention**
- **No magic strings** - eliminates typo-related bugs
- **Clear intent** - `TokenConstants.TokenNames.AccessToken` vs `"access_token"`
- **Easier debugging** - find usages and references easily

## Usage Examples

### **Token Retrieval**
```csharp
// Old way ?
var token = await httpContext.GetTokenAsync("access_token");

// New way ?
var token = await httpContext.GetTokenAsync(TokenConstants.TokenNames.AccessToken);
```

### **Token Request**
```csharp
// Old way ?
var request = new Dictionary<string, string>
{
    ["grant_type"] = "refresh_token",
    ["refresh_token"] = refreshToken
};

// New way ?
var request = new Dictionary<string, string>
{
    [TokenConstants.ParameterNames.GrantType] = TokenConstants.GrantTypes.RefreshToken,
    [TokenConstants.ParameterNames.RefreshToken] = refreshToken
};
```

### **JSON Serialization**
```csharp
// Old way ?
[JsonPropertyName("access_token")]
public string? AccessToken { get; set; }

// New way ?
[JsonPropertyName(TokenConstants.JsonPropertyNames.AccessToken)]
public string? AccessToken { get; set; }
```

### **Authentication Headers**
```csharp
// Old way ?
request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

// New way ?
request.Headers.Authorization = new AuthenticationHeaderValue(TokenConstants.TokenTypes.Bearer, token);
```

## Future Extensions

The `TokenConstants` class can be easily extended for new scenarios:

### **Additional Token Types**
```csharp
public static class TokenNames
{
    // Existing constants...
    public const string DeviceCode = "device_code";
    public const string UserCode = "user_code";
}
```

### **Additional OAuth2 Parameters**
```csharp
public static class ParameterNames
{
    // Existing constants...
    public const string Audience = "audience";
    public const string Resource = "resource";
}
```

### **OIDC-Specific Constants**
```csharp
public static class OidcParameters
{
    public const string IdTokenHint = "id_token_hint";
    public const string LoginHint = "login_hint";
    public const string Prompt = "prompt";
}
```

## Migration Notes

### **No Breaking Changes**
- All existing functionality remains unchanged
- Constants map to the same string values as before
- No user-visible changes

### **Backward Compatibility**
- Old hardcoded strings still work (not recommended)
- Gradual migration possible
- Full IntelliSense support for new constants

### **Best Practices**
- Always use constants for new code
- Migrate existing code during maintenance
- Use IDE "Find and Replace" for bulk migrations

This refactoring significantly improves code quality and maintainability while providing a foundation for future token-related development.