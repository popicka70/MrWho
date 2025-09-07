# MrWho – OpenID Connect Identity & Authorization Service

> Documentation: [Device Authorization (RFC 8628) Custom Implementation](docs/DEVICE_FLOW.md)
> Comprehensive Implementation Guide: [IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
> Persistent Keys & Rotation: [Persistent Signing & Encryption Keys](docs/PERSISTENT_KEYS.md)

A modular, multi-tenant (realm‑aware) OpenID Connect / OAuth 2.1 identity service built on .NET 9, ASP.NET Core Identity and OpenIddict. Includes an administration UI (Blazor + Radzen) and dynamic runtime configuration for clients, realms, scopes, resources, claim types and authentication cookies.

## Key Capabilities
- OpenID Connect & OAuth 2.1 compliant endpoints (authorization, token, userinfo, revocation, end session)
- Multi‑tenant via Realms (logical isolation + default policies)
- Dynamic Client / Realm cookie isolation (per-client or per-realm session cookies) – no restarts
- Rich resource model (Identity Resources + API Resources + API Scopes)
- Configurable Claim Types and claim destinations
- Client‑specific token lifetimes, security, MFA, consent, rate limiting (extensible)
- ASP.NET Core Identity user store with role claims
- Seeding of standard scopes, identity resources, api resources, claim types & default realm/client
- Back‑channel logout support
- Machine-to-machine (client credentials) & interactive (authorization code + PKCE + refresh tokens)
- Pluggable external Identity Providers (OIDC) templates seeded but disabled

---
## Domain Model Concepts

### 1. Realms
A realm groups clients and provides inherited defaults (session policies, token lifetimes, cookie SameSite, security requirements, branding, etc.). You can:
- Enable/disable a whole realm
- Set default session timeout, sliding expiration behavior
- Influence cookie settings when CookieSeparationMode = ByRealm
All clients belong to exactly one realm (default realm seeded as "default").

### 2. Clients (OIDC Applications)
Represent first‑party or third‑party applications.
Key attributes (persisted in DB):
- ClientId / (optional) Client Secret
- Allowed flows: Authorization Code (with PKCE), Client Credentials, Password, Device, Refresh Token
- Redirect URIs / Post‑logout Redirect URIs
- Allowed Scopes
- Permissions (OpenIddict granular permissions list)
- Security settings (require PKCE, secret requirement, consent, MFA policies, etc.)
- Token lifetime overrides (access, refresh, id, authorization code, device code)
- Session timeout overrides (per‑client cookie lifetime if cookie separation applies)
Disabled clients cannot authenticate.

### 3. API Scopes
Scopes represent permission *names* a client can request in tokens (e.g. `api.read`, `api.write`, `profile`, `email`, `offline_access`).
Types:
- Standard Identity/OIDC scopes (openid, profile, email, roles, offline_access)
- API permission scopes (api.read, api.write …)
Scopes map to identity or API resources and drive claim emission.

### 4. Identity Resources
Identity Resources bundle **user identity claims** exposed to clients when corresponding scopes are granted (e.g. `profile` -> name, family_name; `email` -> email, email_verified; `roles` -> role claims). They define:
- Name & DisplayName
- Description
- Enabled flag
- Associated Claim Types
- Claim Destinations (id_token, access_token) – controls where included

### 5. API Resources
API Resources represent protected APIs. They:
- Own a set of scopes (api.read, api.write)
- Can have secrets (for introspection or future scenarios)
- Maintain enabled/disabled state
- Track creation/update metadata
A token referencing a scope implicitly targets the API resource owning that scope.

### 6. Claim Types
Formal registry of claim type identifiers (e.g. `email`, `role`, `given_name`, `tenant_id`). Provides metadata and ensures:
- Consistency (single canonical record per logical claim)
- Association with destinations (id_token / access_token) where applicable
Identity & API resources reuse claim types instead of defining raw strings repeatedly.

### 7. Users
Managed through ASP.NET Core Identity (password hashing, lockouts, MFA, etc.). Seeded examples:
- test@example.com / Test123!
- admin@example.com / Admin123!
Users are linked to roles. Role claims + direct user claims feed token claim emission based on requested scopes.

### 8. Token Types & Lifetimes
Configurable per system, realm (future), and client:
- Access token lifetime
- Refresh token lifetime & reuse policy
- ID token lifetime
- Authorization code lifetime
- Device code lifetime
All resolved through a hierarchy: Client override -> Realm default -> System default.

### 9. Consent & MFA Policies
Clients (or realms) can require user consent and optionally allow “remember consent”. MFA requirements can be enforced dynamically (device trust, adaptive policies planned).

---
## Dynamic Cookie Separation Mechanism
Traditional identity servers often use a single authentication cookie for all interactive clients. MrWho allows isolation to prevent session collisions and enable parallel logins with different accounts across apps.

### Modes (MrWhoOptions.CookieSeparationMode)
1. None (default)
   - Single cookie & scheme: Identity.Application
   - Cookie name: `.AspNetCore.Identity.Application`
2. ByClient
   - Each enabled client gets its own authentication scheme + cookie
   - Scheme pattern: `Identity.Application.{clientId}`
   - Cookie name pattern: `.MrWho.{clientId}`
3. ByRealm
   - One scheme & cookie per realm (shared by clients within realm)
   - Scheme pattern: `Identity.Application.Realm.{realmName}`
   - Cookie name pattern: `.MrWho.Realm.{realmName}`

### Runtime Registration
At startup a background registrar queries the database and dynamically registers the required cookie authentication schemes (no rebuild or manual code changes). If clients/realms change:
- Add/enable new client -> new scheme and cookie appear next startup (hot reloading strategies can extend this)
- Disable client -> scheme ignored during next cycle

### Naming Utilities
`CookieSchemeNaming` centralizes patterns and sanitizes identifiers to safe characters (letters, digits, ., _, -). Prevents malformed cookie names and scheme collisions.

### Request-Time Scheme Resolution
Middleware/services resolve the appropriate scheme based on:
- client_id in query/form (authorization/token endpoints)
- OpenIddict context
- Realm association (when ByRealm)
Fallback ensures graceful behavior if detection fails (default scheme).

### Benefits
- Parallel sessions: log into App A with user1 and App B with user2 simultaneously
- Cleaner logout semantics (logout affects only targeted app when per-client)
- Reduced accidental XSRF or session mix issues across tenants

### Considerations
- More cookies -> Slight browser overhead
- Cross-site flows require SameSite=None when third-party usage expected
- Ensure consistent DataProtection key ring across instances for cluster environments

---
## Flow Overview (Interactive Authorization Code + PKCE)
1. Client redirects user to /connect/authorize with scope set
2. Server authenticates (dynamic cookie scheme chosen)
3. User consents (if required) and returns authorization code
4. Client exchanges code at /connect/token for id_token/access_token/refresh_token
5. API calls authorized using Bearer access_token referencing scopes & claims

## Machine-to-Machine (Client Credentials)
- POST /connect/token with grant_type=client_credentials
- Access token contains only app-level claims + requested API scopes

---
## Discovery & Endpoints
Base URL (development): `https://localhost:7113`
- Discovery: `/.well-known/openid-configuration` (NEVER use underscores)
- Authorization: `/connect/authorize`
- Token: `/connect/token`
- UserInfo: `/connect/userinfo`
- End Session: `/connect/logout` (front-channel) + back-channel endpoint
- Introspection / Revocation (if enabled per client)

---
## Seeding Summary
On first run (with migrations applied) the seeding service creates:
- Default realm ("default")
- Standard scopes (openid, profile, email, roles, offline_access)
- Standard identity resources (profile, email, roles …)
- Standard API resources (and example API scopes)
- Claim types catalog
- Default & demo clients with redirect URIs, scopes, permissions
- Test users & roles
- Disabled templates for external IdPs (Google, etc.)

---
## Admin UI (Blazor + Radzen)
Provides CRUD for:
- Realms
- Clients (flows, secrets, redirect URIs, scopes, token lifetimes)
- Identity Resources (claims, destinations)
- API Resources (scopes, secrets)
- Scopes (linking identity/api resources)
- Claim Types
- Users & Roles
Also shows status indicators (enabled/disabled, standard/custom) and uses dialogs for create/edit/detail views.

---
## Client Integration (Consumer Applications)
Use the helper package (MrWho.ClientAuth) to configure OIDC authentication:
```
builder.Services.AddMrWhoAuthentication(o =>
{
  o.Authority = "https://localhost:7113";
  o.ClientId = "my_app_client";
  o.ClientSecret = "optional-secret"; // confidential clients
  o.Scopes.Add("api.read");
});
```
Optional helpers for per-user or client credentials APIs:
```
builder.Services.AddMrWhoUserAccessTokenApi("DemoApiUser", new Uri("https://localhost:7162"));
builder.Services.AddMrWhoClientCredentialsApi("DemoApiM2M", new Uri("https://localhost:7162"), opt => { /* configure */ });
```

---
## Quick Start (Development)
1. Start PostgreSQL (docker compose file: docker-compose.db.yml)
2. Run EF migrations (dotnet ef database update inside MrWho project)
3. Launch identity server (MrWho)
4. Validate discovery: https://localhost:7113/.well-known/openid-configuration
5. Use seeded client or create new via Admin UI

### Sample Password Grant (development convenience)
```
POST /connect/token
 grant_type=password&client_id=postman_client&client_secret=postman_secret&username=test@example.com&password=Test123!&scope=openid profile email
```

---
## Security Notes
- Never enable AcceptAnyServerCertificate outside development
- Always prefer Authorization Code + PKCE for interactive apps
- Limit scopes to least privilege (e.g. avoid granting api.write when read-only sufficient)
- Rotate client secrets regularly (store outside source control)
- Enable per-client or per-realm cookie isolation for stronger boundary between applications
- Enforce HTTPS (production): set RequireHttpsForCookies / CookieSecurePolicy

---
## Troubleshooting
| Issue | Check |
|-------|-------|
| Discovery fails | Ensure path has hyphen `/.well-known/openid-configuration` |
| No dynamic cookie created | Verify CookieSeparationMode (MrWhoOptions) and client IsEnabled |
| Logout not clearing session | Confirm correct scheme (per-client) and that cookie name matches expected pattern |
| Missing claims in token | Scope requested? Identity/API resource includes claim type? Claim destinations configured? |
| Refresh token invalid | Check UseOneTimeRefreshTokens or lifetime expiration |
| Parallel logins overwrite | Ensure CookieSeparationMode != None |

Logs (debug level) output dynamic registration steps & scheme names.

---
## Extensibility Points
- Add new resource or claim types via Admin UI – emitted without code changes
- Implement additional token customization in emission pipeline (claims, transformations)
- Extend dynamic configuration service for custom per-client policies (risk scoring, device checks)
- Plug external IdPs (OIDC / social) using seeded templates (enable + configure keys)

---
## Roadmap (Indicative)
- Device management & trusted device MFA
- Adaptive risk-based policies
- JWKS rotation automation / key rollover UI
- Fine-grained per-scope consent narratives
- Real-time dynamic cookie (hot add/remove without restart)

---
## License
MIT

---
## References
- OpenIddict: https://documentation.openiddict.com/
- OAuth 2.1 Draft / RFC 6749 / 8252
- OpenID Connect Core & Discovery
- ASP.NET Core Identity