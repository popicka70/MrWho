# Device Authorization (RFC 8628) – Custom Implementation

> Status: Experimental (custom endpoints) – OpenIddict built?in device endpoint is **disabled**. This document describes the bespoke implementation currently active in this branch.

## 1. Overview
The Device Authorization Grant ("Device Code" / RFC 8628) enables input?constrained devices (TVs, consoles, CLI tools) to obtain tokens by pairing with a secondary user?agent (browser on a phone or desktop). 

Our implementation purposefully bypasses (for now) OpenIddict's internal device endpoint helpers so we can:
- Control UX (custom verification page: `/connect/verify`)
- Persist extra metadata (IP/User?Agent for verification, polling telemetry)
- Evolve faster while upstream packages are not yet aligned with our needs

Once OpenIddict support is adopted, we can swap by re?enabling its endpoints and removing the custom controller + TokenHandler branch.

## 2. Endpoints
| Purpose | Method | Path | Auth | Rate Limit Policy |
|---------|--------|------|------|-------------------|
| Device Authorization Request | POST | `/connect/device` | Client auth (public or secret) | `rl.device` (config) |
| User Verification (lookup + approve/deny form) | GET | `/connect/verify?user_code=XXXX-XXXX` | Browser session (logged in) | `rl.verify` (future) |
| User Verification (decision) | POST | `/connect/verify` | Logged in (anti?forgery) | `rl.verify` (future) |
| Token Polling | POST | `/connect/token` | Client auth + `grant_type=urn:ietf:params:oauth:grant-type:device_code` | `rl.token` |

## 3. Data Model
`DeviceAuthorization` table (simplified):

| Field | Description |
|-------|-------------|
| Id | Internal identifier (GUID) |
| DeviceCode | Opaque, high entropy (Base64 URL) – sent only to device |
| UserCode | Human friendly code `XXXX-XXXX` Base32 (no 0/O/I/1) |
| ClientId | Refers to OIDC client (public id) |
| Scope | Space separated list of validated scopes (optional) |
| Status | `pending|approved|denied|expired|consumed` |
| Subject | User Id (after approval) |
| PollingIntervalSeconds | Initial minimum poll interval (default 5) |
| LastPolledAt | Timestamp of last poll – used to emit `slow_down` |
| ExpiresAt | Absolute expiry (default 10 min or client override) |
| ApprovedAt / DeniedAt / ConsumedAt | Lifecycle markers |
| VerificationIp / VerificationUserAgent | Auditing |

### Status Transitions
`pending -> approved -> consumed` (success)

`pending -> denied` (user denied)

`pending -> expired` (time elapsed OR first poll after expiry)

`approved -> consumed` (on successful token response)

## 4. Client Configuration
Per client flags / fields:
- `AllowDeviceCodeFlow` (bool) – must be true.
- `DeviceCodeLifetimeMinutes` – lifetime override (default 10).
- `DeviceCodePollingIntervalSeconds` – minimum poll cadence (default 5).

Admin UI (Clients > Flows & Grants tab) exposes a checkbox *Device Authorization (Device Code) Flow*.

If disabled after codes were issued, existing pending codes will still resolve but no new codes can be created.

## 5. Request / Response Contracts
### 5.1 Device Authorization Request
```
POST /connect/device
Content-Type: application/x-www-form-urlencoded

client_id={client_id}&scope=openid%20profile%20api.read
```
**Response 200**
```json
{
  "device_code": "2B5x…",
  "user_code": "CJTK-A9QF",
  "verification_uri": "https://localhost:7113/connect/verify?user_code=CJTK-A9QF",
  "verification_uri_complete": "https://localhost:7113/connect/verify?user_code=CJTK-A9QF",
  "expires_in": 600,
  "interval": 5
}
```
**Errors**: `invalid_client`, `unauthorized_client`, `invalid_scope`, `invalid_request`.

### 5.2 User Verification (Browser)
GET `/connect/verify?user_code=CJTK-A9QF`
- Redirects to `/connect/login` if unauthenticated.
- Renders details (client name, scopes, expiry) + Approve / Deny buttons.

POST `/connect/verify` (form fields `user_code` & `action=approve|deny`)
- CSRF protected.
- Sets status & auditing metadata.

### 5.3 Token Polling
```
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={client_id}
```
**Interim Errors (400)** per RFC 8628:
| error | When |
|-------|------|
| `authorization_pending` | Still waiting for user approval |
| `slow_down` | Polling faster than allowed (interval breach) |
| `access_denied` | User denied request |
| `expired_token` | Expired prior to approval |
| `invalid_grant` | Replay after consumption / malformed code |

**Success (200)** – Standard token response (access token + optional refresh & id token based on scopes).

## 6. Security Controls
| Control | Description |
|---------|-------------|
| Scope Validation | All requested scopes filtered against client’s assigned scopes (invalid -> `invalid_scope`). |
| High Entropy Codes | 48 random bytes -> Base64Url for `device_code`; short user code but uniqueness enforced within active set. |
| Poll Throttling | Enforced minimum interval; early polls yield `slow_down` and update `LastPolledAt`. |
| One?Time Use | On success status set to `consumed` ? subsequent polls `invalid_grant`. |
| Expiry Enforcement | First poll after expiry returns `expired_token` and marks record `expired`. |
| CSRF Protection | Verification POST includes anti?forgery token. |
| Audit Fields | IP + UserAgent captured on approval/denial. |

### NOT YET IMPLEMENTED (Planned)
- Background sweeper (explicit expiration marking) – current logic marks on access.
- Rate limiting attributes (commented; use middleware or map policies if needed).
- Replay detection metrics / anomaly alerts.
- User notification channel (email/device push) when pairing requested.

## 7. Implementation Touch Points
| Location | Purpose |
|----------|---------|
| `Models/DeviceAuthorization.cs` | Entity definition & status constants. |
| `Data/ApplicationDbContext` | Indexes (DeviceCode unique, UserCode, status/expiry combos). |
| `Controllers/DeviceAuthorizationController` | Custom `/connect/device` & `/connect/verify` endpoints + validation + UI view model. |
| `Views/DeviceAuthorization/Verify.cshtml` | Razor UI for user approval / denial. |
| `Handlers/TokenHandler.cs` | Branch inside token endpoint to process `device_code` grant. |
| `ClientsController` | (Creation) intentionally **does not** add device grant permissions to OpenIddict descriptor now. |
| Admin UI (Clients) | `AllowDeviceCodeFlow` toggle + lifetime numeric field. |

## 8. Differences vs Pure RFC / Upstream Default
| Aspect | RFC 8628 / Upstream | Current Custom |
|--------|---------------------|----------------|
| Endpoint Ownership | Authorization Server built?in | Custom MVC controller |
| Device Grant Permission | Managed by OpenIddict permissions | Omitted (custom logic) |
| Slow Down Algorithm | Incremental interval optional | Simple fixed min interval (‘slow_down’ when too early) |
| Verification UI | Library template | Custom Razor page with scope metadata |
| Cleanup | Background job recommended | Lazy (on poll) – sweeper planned |
| Error Codes | Spec set | Matches (authorization_pending, slow_down, access_denied, expired_token, invalid_grant) |

## 9. Testing Guide
### 9.1 Prerequisites
- A client with `AllowDeviceCodeFlow = true` and required scopes (e.g. `openid profile`).
- Server running locally at `https://localhost:7113`.
- User account credentials to approve.

### 9.2 Step?By?Step (curl)
1. **Request Device Code**
   ```bash
   curl -k -X POST https://localhost:7113/connect/device \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "client_id=mrwho_admin_web&scope=openid%20profile"
   ```
   Capture `device_code`, `user_code`, `verification_uri`, `interval`.

2. **Start Polling** (before approval – expect `authorization_pending` or `slow_down`):
   ```bash
   curl -k -X POST https://localhost:7113/connect/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=REPLACE&client_id=mrwho_admin_web"
   ```

3. **Approve in Browser**
   - Navigate to `verification_uri` (e.g. https://localhost:7113/connect/verify?user_code=CJTK-A9QF)
   - Login if required
   - Click Approve

4. **Poll Again** – Should now return token set (200):
   - If tokens returned: success (record transitions to `consumed`).

5. **Replay Poll** – Expect `invalid_grant` since code consumed.

6. **Denied Scenario** – Repeat but Deny ? poll returns `access_denied`.

7. **Expired Scenario** – Set very short `DeviceCodeLifetimeMinutes`, wait past expiry, then poll ? `expired_token`.

### 9.3 Using Postman
1. Create a POST request to `/connect/device` (x-www-form-urlencoded).
2. Duplicate tab for `/connect/token` with required form fields.
3. Add a delay script to poll at the `interval` boundary (or manually click send).
4. Approve via browser; observe successful token issuance.

### 9.4 Automated Test Skeleton
Pseudo flow (adapt for xUnit / MSTest):
```csharp
// 1. POST /connect/device -> parse JSON
// 2. Assert initial token poll returns authorization_pending
// 3. Simulate approve: directly update entity (or invoke controller) in test scope
// 4. Poll again -> success 200 + access_token
// 5. Poll once more -> invalid_grant
```

### 9.5 Common Pitfalls
| Symptom | Cause | Fix |
|---------|-------|-----|
| `unauthorized_client` | Client flag disabled | Enable `AllowDeviceCodeFlow` |
| `invalid_scope` | Scope not assigned to client | Add scope to client (Admin UI) |
| Always `authorization_pending` | User never approved / wrong user_code | Verify code & approval action |
| Immediate `slow_down` | Poll faster than `interval` | Respect `interval` seconds |
| `invalid_grant` first poll | Typo in device_code | Re-copy from initial response |

## 10. Operational Considerations
| Topic | Guidance |
|-------|----------|
| Monitoring | Track counts of issued, approved, denied, expired codes (add metrics later). |
| Cleanup | Add hosted service to transition lingering `pending` -> `expired` after `ExpiresAt`. |
| Auditing | Export DeviceAuthorization table joins with user + client for compliance logs. |
| Abuse Mitigation | Combine IP-based rate limiting (`rl.device`) + global throttling & CAPTCHAs for UI if abused. |
| Secret Leakage | `device_code` must remain confidential (treat like authorization code). |

## 11. Migration Path to OpenIddict Native Support
1. Re-enable in configuration:
   ```csharp
   options.SetDeviceAuthorizationEndpointUris("/connect/device")
          .SetVerificationEndpointUris("/connect/verify")
          .AllowDeviceCodeFlow()
          .UseAspNetCore().EnableVerificationEndpointPassthrough();
   ```
2. Remove custom `DeviceAuthorizationController` and `DeviceAuthorization` entity / schema if not needed.
3. Drop TokenHandler custom branch (rely on OpenIddict events pipeline).
4. Map existing pending states (optional) ? or clear table.

## 12. Future Enhancements
- Background sweeper + metrics exporter (Prometheus)
- User notification system (email / push) on new pending device request
- Two?step approval (MFA challenge) for privileged scopes
- Front?channel WebSocket push to device after approval (reduce polling latency)
- Adaptive dynamic poll interval (increment when slow_down emitted)
- Device pairing history UI (admin + user self?service)

---
**Revision:** 1.0 • **Last Updated:** {{DATE}}
