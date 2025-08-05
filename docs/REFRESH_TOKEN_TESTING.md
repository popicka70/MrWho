# Testing Refresh Token Functionality

## Quick Fix Instructions

The issue where access tokens expired without automatic refresh has been fixed. Here's what was done and how to test it:

## What Was Fixed

1. **Added `offline_access` scope** - This is required for OpenIddict to issue refresh tokens
2. **Fixed refresh token handler** - Now properly validates refresh tokens and extracts user information
3. **Added automatic refresh** - Tokens are now automatically refreshed before API calls and on page requests
4. **Enhanced debugging** - New debug pages help troubleshoot token issues

## How to Test

### 1. Clear Current Session
- Log out from the admin web application
- Close the browser to clear any cached tokens

### 2. Log In Again
- Navigate to the admin web application (https://localhost:7257)
- Log in with credentials: `admin@mrwho.local` / `MrWhoAdmin2024!`

### 3. Check Refresh Token
- Go to **Identity Server** > **Debug Token Refresh** in the menu
- You should now see:
  - ? **Refresh Token Available: True** (this was previously False)
  - ? **Access Token Available: True**
  - Token expiry time and countdown

### 4. Test Automatic Refresh
1. **Wait for Token to Expire** (or modify token lifetime for faster testing)
2. **Navigate to any page** - tokens should refresh automatically
3. **Make an API call** - use the "Test API Call" button on debug page
4. **Check logs** - should show successful refresh operations

### 5. Manual Testing
On the Debug Token Refresh page:
- Use **"Force Refresh Token"** button to manually test refresh
- Should show success message if working correctly

## What to Expect

**Before the fix:**
- No refresh tokens were issued (`offline_access` scope was missing)
- Users had to log out/in when tokens expired
- API calls would fail after token expiry

**After the fix:**
- Refresh tokens are now issued and stored
- Automatic refresh happens ~5 minutes before token expiry
- Seamless user experience with no forced re-authentication
- API calls automatically get fresh tokens

## Troubleshooting

If refresh tokens are still not available:

1. **Check the database** - The admin client should have `offline_access` scope
2. **Check logs** - Look for token refresh attempts and any errors
3. **Clear browser cache** - Old sessions might not have refresh tokens
4. **Verify configuration** - Ensure OpenIddict server has `OfflineAccess` scope registered

## Configuration Details

The fix involved these key changes:

1. **OpenIdConnect Client**: Added `offline_access` scope
2. **OpenIddict Server**: Registered `OfflineAccess` scope  
3. **Admin Client**: Added `offline_access` to allowed scopes
4. **Token Handler**: Fixed refresh token validation logic
5. **Middleware**: Added proactive token refresh
6. **Delegating Handler**: Automatic refresh before API calls

## Expected Timeline

- **Access Token Lifetime**: 1 hour
- **Refresh Token Lifetime**: 14 days  
- **Refresh Before Expiry**: 5 minutes
- **Automatic Refresh**: On page loads and API calls

The system will now automatically maintain valid tokens throughout user sessions, eliminating the need for manual re-authentication due to token expiry.