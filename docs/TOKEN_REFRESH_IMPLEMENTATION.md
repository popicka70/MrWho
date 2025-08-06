# Token Refresh Implementation - Simplified Redirect-Based Solution

## Overview

This document describes the streamlined token refresh implementation that uses a redirect-based approach to reliably handle token expiry in the admin web application.

## Problem Solved

Previously, when access tokens expired in the admin web application, the system didn't automatically refresh them. This caused:
- API calls to fail with 401 Unauthorized errors
- Users having to manually log out and log in again
- Poor user experience with interrupted workflows

## Solution: Redirect-Based Token Refresh

The implementation uses a **redirect-based approach** that works around Blazor Server limitations by using a standard MVC controller for token refresh operations.

### Key Components

### 1. **Token Refresh Controller** (`TokenController.cs`)

A dedicated MVC controller that handles token refresh outside the Blazor context:

- **Endpoint**: `/token/refresh?returnUrl=...`
- **Benefits**: Full HTTP context control, reliable cookie updates
- **Process**: Refreshes tokens ? Redirects back to original page

### 2. **Token Refresh Service** (`TokenRefreshService.cs`)

A service that handles token refresh logic:
- **`EnsureValidTokenAsync`**: Checks if token needs refreshing and refreshes if necessary
- **`ForceRefreshTokenAsync`**: Forces a token refresh
- **`IsTokenExpiredOrExpiringSoonAsync`**: Determines if token is expired or expiring soon (within 5 minutes)

### 3. **Enhanced Authentication Delegating Handler**

Automatically ensures valid tokens before API calls:
- Checks token validity before each API request
- Automatically refreshes tokens if needed
- Handles refresh failures gracefully

### 4. **Token Refresh Middleware** (`TokenRefreshMiddleware.cs`)

Proactive token refresh for interactive requests:
- Monitors interactive GET requests (excluding static resources)
- Automatically refreshes tokens before they expire
- Smart filtering to avoid unnecessary refresh attempts

### 5. **OpenIddict Configuration**

Enhanced server configuration:
- **Access Token Lifetime**: 1 hour
- **Refresh Token Lifetime**: 14 days
- **Offline Access Scope**: Enabled for refresh tokens
- **Rolling Refresh Tokens**: Disabled for development simplicity

## How It Works

### **Manual Refresh Flow**

1. **User clicks "Force Refresh Token"** on debug page
2. **Browser navigates to `/token/refresh`** with return URL
3. **TokenController refreshes tokens** using standard HTTP context
4. **Browser redirects back** to original page
5. **Updated tokens are immediately available** ?

### **Automatic Refresh Flow**

1. **Interactive Requests**: 
   - Middleware checks token expiry on page loads
   - Refreshes proactively if needed

2. **API Calls**:
   - Delegating handler ensures valid token before each call
   - Refreshes automatically if token is expired/expiring

### **Refresh Process**

1. Extract refresh token from authentication properties
2. Call OpenIddict token endpoint with `grant_type=refresh_token`
3. Validate response and extract new tokens
4. Update authentication properties with new tokens
5. Sign in user again with updated tokens

## Configuration

### **Token Lifetimes**

```csharp
options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60))    // 1 hour access tokens
       .SetRefreshTokenLifetime(TimeSpan.FromDays(14));     // 14 days refresh tokens
```

### **Refresh Timing**

- Tokens are refreshed when they expire within **5 minutes**
- This can be configured in `TokenRefreshService._refreshBeforeExpiryTime`

### **Program.cs Configuration**

```csharp
// Add MVC controllers for token refresh
builder.Services.AddControllers();

// Map controllers after middleware
app.MapControllers();
```

## Error Handling

- **Refresh Failure**: User redirected back with error indication
- **Missing Refresh Token**: Logged as warning, user may need to log in again
- **Network Issues**: Logged as errors, graceful degradation
- **Invalid User**: Refresh denied, user needs to re-authenticate

## Debugging

### **Debug Page**: `/debug-token-refresh`

Features:
- View current token status and expiry times
- Manual token refresh via redirect
- Test API calls with current tokens
- View token refresh configuration

### **Logging**

Comprehensive logging at different levels:
- **Debug**: Token status checks, expiry calculations
- **Information**: Successful refresh operations
- **Warning**: Missing tokens, refresh failures
- **Error**: Exceptions during refresh process

## Benefits

1. **Seamless User Experience**: No more forced logouts due to token expiry
2. **Reliable Token Updates**: Redirect approach guarantees fresh tokens
3. **Improved Security**: Shorter access token lifetimes with automatic refresh
4. **Better Reliability**: Automatic retry logic for API calls
5. **Comprehensive Monitoring**: Detailed logging and debug capabilities
6. **Simplified Architecture**: Single reliable refresh method

## Testing

The implementation can be tested using:

1. **Debug Page**: `/debug-token-refresh` for manual testing
2. **API Calls**: Automatic refresh during normal operation
3. **Time Manipulation**: Modify token lifetimes for faster testing
4. **Browser Navigation**: Test refresh during page navigation

## Future Enhancements

Potential improvements for production deployments:

1. **Token Rotation**: Re-enable refresh token rotation for enhanced security
2. **Retry Logic**: Add exponential backoff for failed refresh attempts
3. **Background Refresh**: Implement background token refresh for long-running sessions
4. **Metrics**: Add performance counters and metrics for monitoring
5. **Configuration**: Make refresh timing and behavior configurable via settings