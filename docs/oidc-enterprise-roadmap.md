# MrWho OIDC Enterprise Readiness Roadmap

Last updated: 2025-09-10

## 1. Purpose
Structured, phased plan to evolve the MrWho OpenID Connect / OAuth2 platform (OpenIddict-based) into an enterprise?grade identity and authorization service. Phases balance protocol completeness, security posture, governance, and operational excellence.

## 2. Current Implemented Capabilities (Baseline)
- Core grants: Authorization Code + PKCE (enforced), Client Credentials, Refresh Token (rolling in non-dev), Password (tests only).
- Endpoints: authorization, token, userinfo, revocation, introspection, end session, discovery.
- Realms (basic model) + per-realm default token lifetime fields enforced at issuance; per?client overrides supported.
- Dynamic DB?backed client + scope management with synchronization to OpenIddict.
- Standard + custom scopes (api.read, api.write, mrwho.use, roles variants).
- Rate limiting (fixed window, IP based) for key endpoints.
- External IdP federation (dynamic OIDC provider registrations from DB).
- Back-channel logout service placeholder; logout endpoint (end session) exposed.
- Basic logging (no structured audit store) + seed users/clients/realms.
- Separation of client cookies (per client) and dynamic policy provider.
- Refresh token rotation (non-dev) enabled implicitly.
- Device Authorization Flow (RFC 8628) – implemented custom endpoints + UI.
- Consent persistence + UI (baseline) with scope diffing.
- Client secret hashing + rotation metadata (PBKDF2) – baseline implementation.
- Persistent signing/encryption keys + rotation scaffolding.
- PAR enablement framework (per-client mode flag) + authorization request caching.
- Initial JAR (JWT Secured Authorization Request) validation & JARM (JWT Secured Authorization Response Mode) packaging (preview – opt?in per client, see Phase 1.5 below).

## 3. Gap Summary (What Is Missing vs Enterprise Targets)
| Category | Key Gaps |
|----------|----------|
| Protocol & Security | Dynamic client registration workflow (governed), token exchange, resource indicators, DPoP, mTLS, full logout notifications (front/back channel events dispatch), JWE encryption for request/response objects, key rotation policy automation (retirement UI), PoP tokens, reference tokens option, advanced JARM modes (fragment/form_post.jwt) |
| Identity & Claims | Claim transformation/mapping policies (per realm/client), attribute release control, SCIM 2.0, groups/roles aggregation, self?service profile & session mgmt, realm claim isolation |
| Client & Governance | Approval workflow (completed for secret rotation, pending for dynamic registration), soft delete/versioning, per-client rate limits/quotas (beyond baseline IP limits), tenant (realm) isolation of keys & policies UI |
| Authentication Assurance | MFA policies (TOTP + WebAuthn in progress), adaptive/risk signals, password breach checks, session concurrency & idle revocation, device fingerprint & management UI (partially implemented), device trust scoring |
| Observability & Ops | Structured audit/event store (in progress), OpenTelemetry metrics/traces, security event streaming (CAEP), deep health/readiness probes, SIEM export, config-as-code export/import (partial), disaster recovery runbooks |
| Token & Session | Resource/audience negotiation (RFC 8707), CAE hooks, session revocation APIs, refresh token reuse detection logging, per-scope audience restrictions |
| Developer & Integration | Dynamic client registration governance (pending), sandbox tenants, scope catalog endpoint, Postman/SDK generation, config diff/rollback, replay test harness improvements |
| Security & Compliance | GDPR export/delete workflows, PII encryption at rest, data retention policies, secret scanning, HSM/KMS for keys, FAPI readiness tasks (nonce auditing, PAR mandatory, JARM hardened) |
| Future Readiness | Passkey-first flows (resident keys), FAPI 2.0 baseline & advanced, GNAP exploration |

## 4. Phased Roadmap
### Phase 1 – Core Protocol Hardening & Key Security (High Priority)
Goal: Close critical protocol/security gaps blocking production adoption.
- Add device authorization (RFC 8628) endpoints (device + verification) + rate limits. (Completed)
- Implement dynamic client registration (protected; admin approval queue). (In progress)
- Hash stored client secrets (PBKDF2/Argon2) + rotation metadata (Created, LastUsed, Expires, Status). (Completed baseline PBKDF2)
- Persistent signing & encryption keys (replace dev certs) + automated rotation framework (publish overlapping JWKS; retirement policy scaffolding). (Initial rotation implemented)
- Enforce per-realm/client token lifetimes during issuance. (Completed)
- Front-channel + back-channel logout notification support (spec compliance events). (Planned – partial placeholder)
- Consent service (UI + storage) – baseline (remember/forget decisions, scope diffing). (Completed baseline)
- Structured audit log (append-only) for auth events, token issuance, admin changes. (Planned – table design done)

### Phase 1.5 – Secure Authorization Request / Response Enhancements (NEW)
Objective: Introduce controlled, opt-in support for hardened authorization requests & responses prior to broader Phase 3 items.
Deliverables:
- PAR operational baseline (per-client ParMode: Disabled / Enabled / Required). (Completed)
- JAR (JWT Secured Authorization Request) – HS256/RS256 signature validation (no JWE yet); request object parameter precedence + mismatch rejection; short exp enforcement; alg allow?list per client.
- JARM (JWT Authorization Response Mode) – response_mode=jwt or per-client JarmMode (Disabled / Optional / Required); signed authorization response with code (+ state, iss, aud, iat, exp). (Initial implementation)
- Client configuration fields: JarMode, JarmMode, RequireSignedRequestObject, AllowedRequestObjectAlgs.
- Discovery metadata extensions: request_parameter_supported, request_uri_parameter_supported, authorization_response_iss_parameter_supported, response_modes_supported += jwt, request_object_signing_alg_values_supported.
- Basic admin surface (internal) for enabling Jar/Jarm modes (UI wiring pending – values stored & honored).
- Tests: valid signed JAR -> normal login flow; tampered JAR -> rejected; JAR required -> missing request/request_uri rejected; JARM -> JWT response packaging & validation.

### Phase 2 – Governance, Assurance & Observability
- MFA stack: TOTP + WebAuthn (attestation caching) + policy binding (per realm/client/scope sensitivity).
- Adaptive/risk signals (IP reputation, geo-impossible travel baseline, device novelty score).
- Policy-driven claim release (per client + scope whitelist + transformation rules).
- SCIM 2.0 provisioning endpoints with realm scoping.
- Per-client rate limits + quotas (token issuance, auth attempts) – move from IP-only.
- Config export/import (GitOps): realms, clients, scopes, policies (JSON schema + checksum).
- OpenTelemetry metrics (latency per grant, error taxonomy, token issuance counts) + tracing.
- Secret rotation workflow (admin UI + scheduled reminders).

### Phase 3 – Advanced OAuth/OIDC & Access Control
- PAR (hard enforcement variants), JAR/JARM hardening (JWE encryption; advanced response modes: fragment.jwt/form_post.jwt).
- Token exchange (RFC 8693) for delegation/impersonation.
- Resource indicators (RFC 8707) + audience negotiation.
- Reference tokens (opaque) + introspection performance cache (distributed) option.
- DPoP + mTLS client auth (selected high-assurance clients).
- Continuous Access Evaluation (event push + revocation reasons) initial.
- Session & refresh token global revocation APIs + reuse detection logging.
- Group/role aggregation service (directory sync adapter abstraction).

### Phase 4 – Compliance, Analytics & Future Readiness
- GDPR workflows: export, delete (anonymize), retention policies.
- PII encryption at rest (field-level; keys via KMS/HSM) + key hierarchy.
- Security Event streaming (CAEP) + SIEM connectors.
- FAPI baseline hardening (nonce enforcement auditing, PAR mandatory, JARM tokens, MTLS/DPoP for confidential clients).
- Passkey-first login UX + resident credential lifecycle management.
- Advanced analytics dashboards (conversion funnel, failure taxonomy clustering, anomaly detection).
- Policy versioning + rollback; diffable history for clients/realms.

## 5. Immediate Sprint Backlog (Updated)
1. Finalize audit log store + writer (append-only semantics + integrity hash prototype).
2. Logout notifications (front + back channel) full implementation + test coverage.
3. JAR/JARM admin UI surfacing (toggle & alg configuration) + documentation.
4. Dynamic client registration approval workflow + integration tests.
5. Metrics scaffolding (auth_requests_total, token_issuance_latency_seconds) – OpenTelemetry export.
6. JWE design spike (request object encryption strategy) – defer implementation.
7. Expand consent expiration logic (invalidate on claim expansion policies, not just scope expansion).

## 6. Data Model Additions (Phase 1 & 1.5)
- ClientSecretHistory: Id, ClientId, SecretHash, Algo, CreatedAt, ExpiresAt, LastUsedAt, Status.
- KeyMaterial: Id, Use (sig/enc), Kid, Algorithm, CreatedAt, ActivateAt, RetireAt, RevokedAt, Status, IsPrimary.
- Consent: Id, UserId, ClientId, GrantedScopes(json), CreatedAt, UpdatedAt, Version.
- AuditEvent: Id, TimestampUtc, Actor (User/Client/System), ActorId, Type, Category, Realm, CorrelationId, Data(json), Severity.
- (NEW) Client.JarMode (Disabled|Optional|Required), Client.JarmMode (Disabled|Optional|Required), Client.RequireSignedRequestObject (bool), Client.AllowedRequestObjectAlgs (CSV/JSON), future: Client.RequireEncryptedRequestObject (deferred), Client.JarmSigningAlg (future override).

## 7. Security Controls (Phase 1 Target State)
| Control | Minimum Implementation |
|---------|------------------------|
| Key Rotation | Scheduled job + overlapping JWKS publication; retire old after grace period |
| Client Secret Storage | Hash (Argon2id preferred) + per-secret metadata + rotation API (PBKDF2 active; Argon2 planned) |
| Consent | Stored decisions; auto-expire on scope expansion (claim expansion future) |
| Logout | Front + back channel events + admin UI session view (in progress) |
| Audit | Append-only table + integrity hash (planned) |
| Token Lifetimes | Realm + client overrides applied centrally in issuance pipeline (Completed) |
| JAR (Phase 1.5) | Signed request object HS256/RS256; exp <= 5m; mismatch rejection; optional per-client or required |
| JARM (Phase 1.5) | Signed JWT authorization response (code + state); opt-in per client; response_mode=jwt support |

## 8. Open Issues to Clarify
- Multi-region deployment requirements (affects key replication strategy?).
- External directory sources (AD/LDAP/HR) priority for group synchronization.
- Minimal viable risk signals for adaptive auth (start with IP/geo?).
- Regulatory targets (GDPR only or also SOC2 / ISO / HIPAA?).
- JARM response mode variants needed (fragment/form_post) + FAPI alignment timeline.
- Request object encryption (JWE) priority relative to mTLS/DPoP.

## 9. Acceptance Criteria Examples (Phase 1 & 1.5 Highlights)
- Device Flow: POST /connect/device returns device_code + user_code; polling token endpoint yields pending/slow_down/authorization_pending then tokens; tests cover positive + rate limit.
- Secret Hashing: Plain secrets migrated; no plaintext retrievable; verification passes existing clients; rotation invalidates prior secret after grace period.
- Key Rotation: New key published; tokens signed by new key after switch; old key validates existing tokens until retirement timestamp.
- Consent: First-time authorization prompts; subsequent requests without new scopes skip prompt; revoking consent removes stored grant and forces prompt.
- Audit: Creating client writes audit record (Type=client.create); fetching audit list by correlation ID returns expected sequence.
- JAR: Signed request with HS256 using client secret resolves parameters; tampered signature rejected with invalid_request_object; missing request when JarMode=Required rejected; conflicting parameter (e.g., scope in URL differs from request object) rejected.
- JARM: When JarmMode=Required or response_mode=jwt, authorization response returns single JWT (response value) containing code + state + iss + aud with valid signature; invalid signature tampering detected by client test harness.

## 10. Risks & Mitigations
| Risk | Mitigation |
|------|------------|
| Feature creep delays hardening | Lock Phase 1 + 1.5 scope; defer advanced JARM variants & JWE to Phase 3 |
| Secret migration disruption | Dual-verify window; accept old plaintext until first hash write completes |
| Key rotation outage | Stage rotation in non-prod; smoke test issuance + validation before production cutover |
| Consent UX confusion | Provide clear diff list of newly requested scopes |
| JAR misuse (alg none) | Enforce RequireSignedRequestObject + alg allow-list per client |
| Large request objects abuse | Authorization request caching with size limits + short exp enforcement |

## 11. Tracking & Metrics (Introduce with Phase 2)
- Metric: auth_requests_total{grant_type, outcome}
- Metric: token_issuance_latency_seconds (histogram)
- Metric: refresh_token_reuse_detected_total
- Metric: consent_prompt_rate (prompts / authorizations)
- Metric: active_sessions{realm}
- (Planned) jar_requests_total{mode,outcome,alg}; jarm_responses_total{mode,outcome}

## 12. Next Steps (Actionable)
1. Surface JarMode/JarmMode & alg configuration in admin UI (client edit > Flows & Grants tab).
2. Add EF migration for new Client JAR/JARM fields (JarMode, JarmMode, RequireSignedRequestObject, AllowedRequestObjectAlgs).
3. Harden JAR validation: add jti replay protection & optional clock skew; size limit & configurable exp max.
4. Extend discovery document handler to advertise supported algs dynamically from active keys.
5. Implement audit events for JAR/JARM failures (category=auth.security).
6. Implement full logout notifications.
7. Build audit writer + enrich existing critical operations.
8. Begin metrics instrumentation for authorization/token endpoints.
9. Plan JWE (encryption) design for request objects (select mandatory alg set + key distribution strategy).

---
Prepared for: MrWho Identity Platform
