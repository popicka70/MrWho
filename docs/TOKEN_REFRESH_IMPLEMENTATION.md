# Token Refresh Implementation

## Overview

This document describes the automatic token refresh implementation that fixes the issue where access tokens would expire in the admin web application, requiring users to log out and log in again.

## Problem

Previously, when access tokens expired in the admin web application, the system didn't automatically refresh them. This caused:
- API calls to fail with 401 Unauthorized errors
- Users having to manually log out and log in again
- Poor user experience with interrupted workflows

## Solution

The implementation includes several components working together to provide seamless token refresh:

### 1. Fixed Refresh Token Handler (`TokenHandler.cs`)

**Before**: The `HandleRefreshTokenGrant` method used hardcoded placeholder values.

**After**: Properly validates refresh tokens and extracts actual user information:
- Authenticates the refresh token
- Validates the user still exists and is valid
- Creates fresh identity with current user information
- Includes user roles and claims

### 2. Token Refresh Service (`TokenRefreshService.cs`)

A dedicated service that handles token refresh logic:
- **`EnsureValidTokenAsync`**: Checks if token needs refreshing and refreshes if necessary
- **`ForceRefreshTokenAsync`**: Forces a token refresh using the refresh token
- **`IsTokenExpiredOrExpiringSoonAsync`**: Determines if token is expired or expiring soon (within 5 minutes)

**Key Features**:
- Automatic token expiry detection using JWT parsing
- Secure token refresh using OpenIddict token endpoint
- Proper authentication property updates
- Comprehensive error handling and logging

### 3. Enhanced Authentication Delegating Handler

**Before**: Only added tokens to API requests without refresh capability.

**After**: Automatically ensures valid tokens before API calls:
- Checks token validity before each API request
- Automatically refreshes tokens if needed
- Handles refresh failures gracefully
- Provides detailed logging for troubleshooting

### 4. Token Refresh Middleware (`TokenRefreshMiddleware.cs`)

Proactive token refresh for interactive requests:
- Monitors interactive GET requests (excluding static resources)
- Automatically refreshes tokens before they expire
- Non-blocking - doesn't fail requests if refresh fails
- Smart filtering to avoid unnecessary refresh attempts

### 5. OpenIddict Configuration

Enhanced server configuration:
- **Access Token Lifetime**: 1 hour (configurable)
- **Refresh Token Lifetime**: 14 days (configurable)
- Proper grant type support including refresh tokens

## Configuration

### Token Lifetimes

```csharp
options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60))    // 1 hour access tokens
       .SetRefreshTokenLifetime(TimeSpan.FromDays(14));     // 14 days refresh tokens
```

### Refresh Timing

- Tokens are refreshed when they expire within **5 minutes**
- This can be configured in `TokenRefreshService._refreshBeforeExpiryTime`

## How It Works

### Automatic Refresh Flow

1. **Interactive Requests**: 
   - Middleware checks token expiry on page loads
   - Refreshes proactively if needed

2. **API Calls**:
   - Delegating handler ensures valid token before each call
   - Refreshes automatically if token is expired/expiring

3. **Manual Operations**:
   - Debug page allows manual token status checking
   - Force refresh capability for troubleshooting

### Refresh Process

1. Extract refresh token from authentication properties
2. Call OpenIddict token endpoint with `grant_type=refresh_token`
3. Validate response and extract new tokens
4. Update authentication properties with new tokens
5. Sign in user again with updated tokens

## Error Handling

- **Refresh Failure**: User continues with current session, may need to re-authenticate
- **Missing Refresh Token**: Logged as warning, user may need to log in again
- **Network Issues**: Logged as errors, graceful degradation
- **Invalid User**: Refresh denied, user needs to re-authenticate

## Debugging

### Debug Pages

- **`/debug-tokens`**: View current token information and test API calls
- **`/debug-token-refresh`**: Test token refresh functionality and view status

### Logging

Comprehensive logging at different levels:
- **Debug**: Token status checks, expiry calculations
- **Information**: Successful refresh operations
- **Warning**: Missing tokens, refresh failures
- **Error**: Exceptions during refresh process

## Testing

The implementation can be tested using:

1. **Debug Pages**: Manual testing of refresh functionality
2. **API Calls**: Automatic refresh during normal operation
3. **Time Manipulation**: Modify token lifetimes for faster testing
4. **Network Simulation**: Test refresh under various network conditions

## Benefits

1. **Seamless User Experience**: No more forced logouts due to token expiry
2. **Improved Security**: Shorter access token lifetimes with automatic refresh
3. **Better Reliability**: Automatic retry logic for API calls
4. **Comprehensive Monitoring**: Detailed logging and debug capabilities
5. **Graceful Degradation**: Handles failures without breaking user workflows

## Future Enhancements

Potential improvements for production deployments:

1. **Token Rotation**: Implement refresh token rotation for better security
2. **Retry Logic**: Add exponential backoff for failed refresh attempts
3. **Background Refresh**: Implement background token refresh for long-running sessions
4. **Metrics**: Add performance counters and metrics for monitoring
5. **Configuration**: Make refresh timing and behavior configurable via settings