# OBO vs M2M Comparison Demo - Testing Guide

## Quick Start Testing

### Prerequisites

1. Docker Compose is running with all services (MrWhoOidc, obo-demo-api, dotnet-mvc-client)
2. You have access to the MrWhoOidc admin UI credentials
3. The `dotnet-mvc-demo` client is properly configured in OIDC with `client_credentials` grant

### Test Scenario 1: OBO Demo Only

**Duration:** ~2 minutes

**Steps:**

1. Navigate to `https://localhost:5001` (dotnet-mvc-client)
2. Sign in with a test user account
3. Click "OBO Demo" in navigation
4. Click "Call API on behalf of me" button
5. **Verify:**
   - Response shows `message = "Called on behalf of user"`
   - `subject` shows the user ID
   - `name` and `email` show user information
   - `actor` shows `"dotnet-mvc-demo"` (the client)
   - `userInfo` contains full user profile from IdP

**Expected Behavior:**
- Token exchange grant is used
- User context is preserved in the token
- The API can identify both the user and the client

---

### Test Scenario 2: M2M Demo Only

**Duration:** ~2 minutes

**Steps:**

1. Navigate to `https://localhost:5001` (still logged in as user)
2. Click "OBO vs M2M" in navigation
3. Click "M2M Only" button
4. **Verify:**
   - Response shows `message = "Called as machine identity (M2M / Client Credentials flow)"`
   - `type = "machine"`
   - `clientId` shows `"dotnet-mvc-demo"`
   - `subject` shows client ID
   - No `name`, `email`, or `actor` fields
   - No user context

**Expected Behavior:**
- Client credentials grant is used
- Machine identity is used instead of user
- No user information is available
- The API only knows about the application

---

### Test Scenario 3: Side-by-Side Comparison

**Duration:** ~3 minutes

**Steps:**

1. Remaining on "OBO vs M2M" page
2. Click "Call API with Both Flows" button
3. Wait for both requests to complete
4. **Verify OBO Response (green card):**
   - Type: `user`
   - Subject matches logged-in user
   - Name and email visible
   - Actor shows client ID
5. **Verify M2M Response (blue card):**
   - Type: `machine`
   - ClientId shows `dotnet-mvc-demo`
   - No user information
   - Different subject from OBO

**Expected Behavior:**
- Both calls complete successfully
- Clear visual difference between the two responses
- Comparison table below explains the differences

---

### Test Scenario 4: Configuration Verification

**Duration:** ~5 minutes

**Steps:**

1. Navigate to MrWhoOidc Admin UI: `https://localhost:8443/admin`
2. Find and edit `dotnet-mvc-demo` client
3. **Verify Settings:**
   - ✅ Client ID: `dotnet-mvc-demo`
   - ✅ Grant Types includes:
     - `authorization_code`
     - `refresh_token`
     - `urn:ietf:params:oauth:grant-type:token-exchange`
     - `client_credentials` (newly added)
   - ✅ Scopes include: `openid`, `profile`, `email`, `offline_access`, `api.read`
   - ✅ OBO enabled with target audience: `obo-demo-api`

4. Verify `obo-demo-api` client exists with audience `obo-demo-api`

**Expected Behavior:**
- Client is configured for both OBO and M2M flows
- Seed manifest correctly applied

---

### Test Scenario 5: Error Handling

**Duration:** ~2 minutes

**Steps:**

1. On "OBO vs M2M" page
2. **Test 5a: Network Error Simulation**
   - Stop obo-demo-api container: `docker stop obo-demo-api`
   - Click "Call API with Both Flows"
   - **Verify:** Error message displayed
   - **Verify:** Page remains usable
   - Restart container: `docker start obo-demo-api`

3. **Test 5b: Invalid Token (optional)**
   - Modify M2MApi base address to point to wrong port
   - Click "M2M Only"
   - **Verify:** Appropriate error message shown
   - Revert configuration

**Expected Behavior:**
- Errors are caught and displayed gracefully
- Application doesn't crash
- User can retry

---

### Test Scenario 6: Token Inspection

**Duration:** ~3 minutes

**Steps:**

1. On "OBO vs M2M" page after calling both APIs
2. Expand "Raw JSON Response" details for both cards
3. **For OBO Response JSON:**
   - Search for `"actor"` - should be present
   - Search for `"name"` - should be present
   - Search for `"email"` - should be present
   - Search for `"userInfo"` - should contain full user object

4. **For M2M Response JSON:**
   - Search for `"clientId"` - should show client ID
   - Search for `"actor"` - should NOT be present
   - Search for `"name"` - should NOT be present
   - Search for `"email"` - should NOT be present

**Expected Behavior:**
- JSON is properly formatted and readable
- OBO token contains user context
- M2M token contains only machine context

---

### Test Scenario 7: Performance (Optional)

**Duration:** ~5 minutes

**Steps:**

1. On "OBO vs M2M" page
2. Open browser developer tools (F12)
3. Go to Network tab
4. Click "Call API with Both Flows"
5. **Observe:**
   - Token endpoint calls (may be cached)
   - API endpoint calls
   - Response times
6. Click again to see token caching in action:
   - Second call should be faster (tokens cached)

**Expected Behavior:**
- Token caching reduces response time on subsequent calls
- Network requests show efficient token reuse

---

### Test Scenario 8: User Logout and Re-login

**Duration:** ~3 minutes

**Steps:**

1. On any page in the app
2. Click "Sign out"
3. **Verify:** Redirected to login page
4. Sign in with **different user** account
5. Navigate to "OBO vs M2M"
6. Click "OBO Only"
7. **Verify:**
   - `subject` shows NEW user ID
   - `name` and `email` show NEW user information
   - `actor` still shows `dotnet-mvc-demo`

**Expected Behavior:**
- User context changes with login
- Client context remains constant
- Proper session management

---

## Automation Testing (Optional)

If you have the Playwright test infrastructure set up:

### Create Basic Smoke Tests

**Test: OBO Flow**
```csharp
[Test]
public async Task OboDemo_CallsApiSuccessfully()
{
    await page.GotoAsync("https://localhost:5001");
    await page.ClickAsync("text=Sign in");
    // ... authenticate ...
    await page.ClickAsync("text=OBO Demo");
    await page.ClickAsync("button:has-text('Call API')");
    var response = await page.TextContentAsync("[type='user']");
    Assert.Contains("user", response);
}
```

**Test: M2M Flow**
```csharp
[Test]
public async Task M2mDemo_CallsApiSuccessfully()
{
    // ... login first ...
    await page.GotoAsync("https://localhost:5001/TokenComparison");
    await page.ClickAsync("button:has-text('M2M Only')");
    var response = await page.TextContentAsync("[type='machine']");
    Assert.Contains("machine", response);
}
```

**Test: Side-by-Side Comparison**
```csharp
[Test]
public async Task ComparisonPage_ShowsBothFlows()
{
    // ... login first ...
    await page.GotoAsync("https://localhost:5001/TokenComparison");
    await page.ClickAsync("button:has-text('Call API with Both Flows')");
    var oboCard = await page.TextContentAsync("[type='user']");
    var m2mCard = await page.TextContentAsync("[type='machine']");
    Assert.NotEmpty(oboCard);
    Assert.NotEmpty(m2mCard);
}
```

---

## Troubleshooting

### Issue: "Failed to acquire client-credentials token"

**Cause:** Client credentials grant not enabled on client

**Solution:**
1. Check Admin UI for `dotnet-mvc-demo` client
2. Verify `client_credentials` is in Grant Types
3. Re-seed if needed: `docker-compose restart mrwho-oidc`

### Issue: M2M API call returns 401 Unauthorized

**Cause:** Token validation failing

**Solution:**
1. Verify obo-demo-api has correct issuer URL
2. Check JWKS cache is working
3. Verify token hasn't expired (check `expiresAt` field)

### Issue: OBO call succeeds but M2M fails

**Cause:** Token caching or configuration issue

**Solution:**
1. Clear browser cache and cookies
2. Restart dotnet-mvc-client: `docker restart dotnet-mvc-client`
3. Verify both flows are configured in appsettings.json

### Issue: User info not populated in OBO response

**Cause:** UserInfo endpoint call failing

**Solution:**
1. Check MrWhoOidc `/userinfo` endpoint is working
2. Verify access token has correct scopes
3. Check logs: `docker logs obo-demo-api`

---

## Performance Benchmarks

Expected response times (after first call when tokens are cached):

| Scenario | Expected Time | Notes |
|----------|--------------|-------|
| OBO call | 50-200ms | First call: 500ms+ (token exchange + userinfo) |
| M2M call | 30-100ms | First call: 300-500ms (token acquisition) |
| Both parallel | 50-200ms | Both cached; server response time |

---

## Sign-off Checklist

- [ ] OBO demo works and shows user context
- [ ] M2M demo works and shows machine context
- [ ] Side-by-side comparison displays both responses
- [ ] Comparison table is visible and readable
- [ ] No build errors or warnings
- [ ] No 404 errors in browser console
- [ ] Navigation links work correctly
- [ ] Error handling works gracefully
- [ ] Page is responsive on different screen sizes
- [ ] Configuration is environment-appropriate (dev/prod)

---

## Notes

- All tests assume development environment with self-signed certificates
- User accounts must exist in MrWhoOidc for testing
- Token caching is transparent but affects performance measurements
- The comparison page requires authenticated user (even though M2M doesn't need it)
