# MrWho Identity Platform – Implementation Guide

_Last updated: 2025-09-05_

This document provides a deep technical overview of the current implementation of the MrWho OpenID Connect / OAuth 2.1 server built on .NET 9, ASP.NET Core, Identity and OpenIddict. It complements the high?level roadmap.

## 1. Solution Architecture
Projects (core only):
- MrWho (OIDC server – endpoints, OpenIddict host, EF Core, Identity)
- MrWho.Shared (shared enums, DTOs, option models)
- MrWhoAdmin.Web (Blazor Server admin UI with Radzen components)
- MrWho.ClientAuth (helper library for downstream clients: login/logout helpers, back?channel logout consumer)
- Demo projects (MrWhoDemo1, MrWhoDemoApi, Kotlin / other samples) for integration validation

Cross?cutting: Mediator-style request handlers, dynamic configuration loaders, seeding services, and background hosted services.

## 2. OpenIddict Server Configuration
Configured via AddMrWhoOpenIddict:
- Endpoints: /connect/authorize, /connect/token, /connect/userinfo, /connect/revocation, /connect/introspect, /connect/logout, discovery (/.well-known/openid-configuration)
- Flows enabled: Authorization Code (PKCE enforced globally), Client Credentials, Refresh Token, (Password only in Testing), Device (planned)
- Development certs for signing/encryption (rotation framework planned – persistent key material Phase 1)
- Access tokens are JWT (encryption disabled for API compatibility)
- Scopes registered: openid, email, profile, roles, offline_access, api.read, api.write, mrwho.use, roles.* variants

Custom handlers:
- CustomUserInfoHandler: dynamic claim assembly with fallback to scope semantics when identity resources absent

## 3. Dynamic Client Registration (MVP)
Endpoint: POST /connect/register (protected – requires authenticated admin user for now).

Specification coverage:
- Accepts RFC 7591 subset JSON: client_name, redirect_uris, post_logout_redirect_uris, grant_types, response_types, scope, token_endpoint_auth_method
- Supported grant_types: authorization_code, client_credentials, refresh_token (password/implicit rejected)
- Supported response_types: code
- PKCE always enforced when authorization_code requested
- Client secret auto-generated for confidential or machine style clients (client_secret_post semantics). Public clients created with no secret
- Scopes filtered to those that exist & enabled; openid automatically added for code flow
- Clients stored in default realm; multi-realm selection & approval workflow pending
- Secret currently stored plaintext (hash + history planned – Phase 1)
- Registration endpoint NOT yet advertised in discovery (will add once compatible handler or OpenIddict version upgrade is in place)
- Response includes client_id, client_secret (if any), timestamps, granted lists

Future enhancements: initial access tokens, software statements, update/delete (RFC 7592), secret rotation metadata, per-realm isolation, audit event emission.

## 4. Data Model (Key Tables)
- Realms: logical tenancy + default token lifetimes and branding
- Clients (+ related: ClientRedirectUri, ClientPostLogoutUri, ClientScope, ClientPermission, ClientAudience, ClientRole)
- Scopes (identity/resource); IdentityResources + IdentityResourceClaims
- Users (ASP.NET Core Identity) + roles + user claims
- Planned additions: ClientSecretHistory, KeyMaterial, Consent, AuditEvent

Client record holds extensive optional overrides: token lifetimes, session behavior, MFA, consent, logout URIs, rate limits, branding, access endpoint flags.

## 5. Seeding
Single initialization pipeline (InitializeDatabaseAsync) seeds:
- Standard scopes & identity resources
- Realms: admin, demo, default
- Core clients: admin web, demo interactive, m2m clients
- Users: admin, demo test users
- Dynamic synchronization into OpenIddict (descriptor constructed per client)

Backfill logic corrects legacy permission formats (scope permission normalization to scp:*). Missing endpoint access flags patched.

## 6. Authentication & Session Model
- ASP.NET Core Identity for interactive users
- Cookie separation modes (None, ByClient, ByRealm) configured by MrWhoOptions.CookieSeparationMode
- DynamicClientCookieService enumerates enabled clients and registers cookie schemes at startup
- Middleware (ClientCookieMiddleware) selects correct scheme per request based on client_id and realm mapping

Benefits: parallel logins, isolation of sign-out, reduced cross-app session collision.

## 7. Authorization Flows
Authorization Code + PKCE (interactive): standard flow with enforced PKCE for all code clients.
Client Credentials: machine-to-machine; access tokens contain application scope grants.
Refresh Tokens: rolling tokens (disabled only in Development for easier testing). Rotation detection logging planned.
Password Grant: available only under Testing environment (for integration tests). To be removed from production builds.
Device Authorization: planned (endpoint scaffolding placeholder; will add /connect/device + verification page + interval/backoff compliance).

## 8. Token Lifetime Resolution
Hierarchy: Client override -> Realm defaults -> System fallback.
Client helper methods: GetEffectiveAccessTokenLifetime, GetEffectiveRefreshTokenLifetime, GetEffectiveAuthorizationCodeLifetime.
Enforcement in issuance pipeline (per-realm/client override middleware) is in backlog (Phase 1 task).

## 9. Scope & Claim Mapping
- Scopes drive claim inclusion (identity resources if present; fallback additive logic in CustomUserInfoHandler)
- Standard identity resources define claim sets for profile/email/roles/phone/address
- Role claims aggregated from ASP.NET Core Identity roles (future: group aggregation + directory sync)
- mrwho.use scope reserved for administrative API interactions

## 10. Logout Support
Front-channel: /connect/logout (end session) endpoint (OpenIddict). Clients may supply post_logout_redirect_uri.
Back-channel: BackChannelLogoutService placeholder triggers HTTP POST to registered client back-channel logout endpoints (client fields BackChannelLogoutUri etc.). Client library exposes /signout-backchannel endpoint mapping which parses logout_token (JWT or dev JSON fallback) and signs user out of its cookie.

Future: event audit, session revocation UI, front-channel iframe integration, sid claim correlation, global session management.

## 11. Rate Limiting
ASP.NET Core Rate Limiter policies (fixed window) applied per endpoint category: rl.login, rl.register, rl.token, rl.authorize, rl.userinfo (+ placeholders rl.device, rl.verify). Partition key: remote IP.
Planned: evolve to per-client quotas (Phase 2) and dynamic Redis-backed distributed limiter.

## 12. Dynamic Permissions / OpenIddict Synchronization
Descriptor builder (OidcClientService.BuildDescriptor):
- Grants & endpoints only for allowed flows
- Scope permissions normalized (scp:*)
- Adds endpoint permissions (endpoints.userinfo, endpoints.revocation, endpoints.introspection) based on client flags
- Redirect & post-logout URIs injected
Update vs create decided by FindByClientIdAsync. Errors logged & bubbled to fail early (prevent silent invalid_client issues).

## 13. Observability & Logging
Current: standard ASP.NET Core logging (structured logging via ILogger). Debug endpoints expose runtime config (client flags, OpenIddict application permissions, user claims, scope synchronization state). Planned: OpenTelemetry traces + metrics, structured audit event store, CAEP security streaming.

## 14. Security Posture (Current vs Planned)
Current:
- PKCE enforced for all code flows
- HTTPS cookie secure policy enforced outside Development
- Session cookie isolation capability
- Refresh token rotation (non-development)
- Basic back-channel logout
- Restricted password grant usage
Planned (Phase 1/2):
- Client secret hashing + rotation metadata
- Key material persistence + automated rotation
- Consent persistence & diff prompts
- Audit event integrity (hash chain optional)
- MFA (TOTP / WebAuthn) + adaptive risk scoring
- Argon2id hashing for secrets & user password breach checks

## 15. Extensibility Points
- Add/modify scopes and identity resources at runtime (synchronized to OpenIddict)
- Extend Authorization / Token handlers (custom events / pipeline insertion)
- Implement future Device Authorization handler + verification UI
- Add claim transformation policies (per realm/client) to pipeline (planned service abstraction)
- Add secret rotation & hashing service intercepting client creation/update

## 16. Limitations / Known Gaps
- Dynamic registration not discoverable (metadata entry omitted until handler version alignment)
- No client update (PATCH/PUT) or delete self-service – admin UI only
- Plaintext client secret storage (migration required)
- No persistent key store (dev certs only)
- Consent + audit tables not implemented yet
- Per-client rate quota enforcement not yet active (only coarse IP limiter)
- No token exchange / PAR / JAR / DPoP / mTLS (future phases)

## 17. Deployment Considerations
- DataProtection keys are persisted in DB (cluster-safe). Ensure single shared database or external key ring in multi-region.
- ForwardedHeaders enabled – configure trusted proxies in production
- Use environment variables OPENIDDICT__ISSUER and database connection string settings for container deployments
- Plan key rotation before enabling long-lived refresh tokens between rotations

## 18. Roadmap Alignment Snapshot
Implemented: dynamic clients (DB + sync), dynamic registration MVP (admin gated), cookie separation, base endpoints, scope/resource/identity resource seeding, back-channel logout stub.
In Progress / Next (Phase 1): key rotation, secret hashing + history, consent persistence, token lifetime enforcement in issuance, structured audit store, device flow.

## 19. Testing Strategy
- Integration tests (Testing environment) enable password grant to simplify token acquisition
- In-memory / EnsureCreated DB for speed (test helpers in MrWho.Testing)
- Planned: device flow simulator, replay attack harness, secret rotation regression tests, dynamic registration contract tests.

## 20. Future Enhancements (Highlights)
- RFC 8707 resource indicators & audience negotiation
- Reference tokens + distributed introspection cache
- Continuous Access Evaluation (event push) integration
- SCIM 2.0 provisioning endpoints
- GDPR export/delete pipelines and retention policies
- FAPI baseline & advanced security profile options

---
For architectural questions or proposed extensions, update this file and cross?reference the roadmap (docs/oidc-enterprise-roadmap.md).
