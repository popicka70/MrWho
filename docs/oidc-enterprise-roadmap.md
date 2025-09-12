# MrWho OIDC Enterprise Readiness Roadmap

Last updated: 2025-09-12 (Assessment + near-term prioritization added)

## 1. Purpose
Structured, phased plan to evolve the MrWho OpenID Connect / OAuth2 platform (OpenIddict-based) into an enterprise–grade identity and authorization service. Phases balance protocol completeness, security posture, governance, and operational excellence.

## 2. Current Implemented Capabilities (Baseline)
- Core grants: Authorization Code + PKCE (enforced), Client Credentials, Refresh Token (rolling in non-dev), Password (tests only).
- Endpoints: authorization, token, userinfo, revocation, introspection, end session, discovery.
- Realms (basic model) + per-realm default token lifetime fields enforced at issuance; per–client overrides supported.
- Dynamic DB–backed client + scope management with synchronization to OpenIddict.
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
- JAR (JWT Secured Authorization Request) initial + hardening (HS256/RS256 validation, exp <= 5m, mismatch rejection, per-client alg allow-list, jti replay protection, size limit, configurable exp/clock skew) – Phase 1.5 baseline COMPLETE.
- JARM (JWT Secured Authorization Response Mode) baseline packaging (response_mode=jwt, iss/aud/iat/exp, signed) – Phase 1.5 baseline COMPLETE.
- Realm default configuration page now includes JAR/JARM defaults (JarMode, JarmMode, RequireSignedRequestObject, AllowedRequestObjectAlgs) – UI FIX COMPLETE.

## 3. Gap Summary (What Is Missing vs Enterprise Targets)
| Category | Key Gaps |
|----------|----------|
| Protocol & Security | Dynamic client registration workflow (governed), token exchange, resource indicators, DPoP, mTLS, full logout notifications (front/back channel events dispatch), JWE encryption for request/response objects, key rotation policy automation (retirement UI), PoP tokens, reference tokens option, advanced JARM modes (fragment/form_post.jwt), JARM encryption, advanced audience negotiation, configurable symmetric secret policy (algorithm-based min lengths, enforcement & downgrade) |
| Identity & Claims | Claim transformation/mapping policies (per realm/client), attribute release control, SCIM 2.0, groups/roles aggregation, self–service profile & session mgmt, realm claim isolation |
| Client & Governance | Approval workflow (dynamic registration), soft delete/versioning, per-client rate limits/quotas, tenant (realm) isolation of keys & policies UI |
| Authentication Assurance | MFA policies (TOTP + WebAuthn in progress), adaptive/risk signals, password breach checks, session concurrency & idle revocation, device fingerprint & management UI, device trust scoring |
| Observability & Ops | Structured audit/event store, OpenTelemetry metrics/traces, security event streaming (CAEP), deep health/readiness probes, SIEM export, config-as-code export/import (full), disaster recovery runbooks |
| Token & Session | Resource/audience negotiation (RFC 8707), CAE hooks, session revocation APIs, refresh token reuse detection logging, per-scope audience restrictions |
| Developer & Integration | Dynamic client registration governance, sandbox tenants, scope catalog endpoint, Postman/SDK generation, config diff/rollback, replay test harness improvements |
| Security & Compliance | GDPR export/delete workflows, PII encryption at rest, data retention policies, secret scanning, HSM/KMS for keys, FAPI readiness tasks (nonce auditing, PAR mandatory, JARM hardened variants, JWE) |
| Future Readiness | Passkey-first flows, FAPI 2.0 baseline & advanced, GNAP exploration |

## 4. Phased Roadmap
### Phase 1 – Core Protocol Hardening & Key Security (High Priority)
Goal: Close critical protocol/security gaps blocking production adoption.
- Device authorization (RFC 8628) – COMPLETE
- Dynamic client registration (protected; admin approval queue) – IN PROGRESS
- Client secret hashing + rotation metadata – BASELINE COMPLETE
- Persistent signing & encryption keys + rotation framework – INITIAL COMPLETE
- Per-realm/client token lifetimes – COMPLETE
- Front/back channel logout notifications – PARTIAL (back-channel helper + placeholder; full events pending)
- Consent service baseline – COMPLETE
- Structured audit log (append-only) – SCHEMA READY (writer pending)
- Configurable symmetric client secret policy (minimum entropy/length per HS* algorithm, validation & admin warnings) – PLANNED

### Phase 1.5 – Secure Authorization Request / Response Enhancements (NEW)
Objective: Controlled, opt-in hardened authorization requests & responses.
Deliverables (Status):
- PAR baseline (per-client ParMode) – COMPLETE
- JAR validation: HS256/RS256, precedence, mismatch rejection, short exp enforcement – COMPLETE
- HARDENING: jti replay protection, size limit, configurable exp max, clock skew – COMPLETE
- JAR per-client alg allow-list & RequireSignedRequestObject – COMPLETE (UI pending at client level)
- JARM: response_mode=jwt and per-client JarmMode; signed JWT (code, state, iss, aud, iat, exp) – COMPLETE
- Discovery metadata extensions – COMPLETE
- Admin surface (JarMode/JarmMode/algs) – IN PROGRESS (client-level UI wiring pending; realm defaults done)
- Tests (positive + tamper) – INITIAL (JarTests) – NEED expansion for replay & size limit
- Add enforcement & configuration UI for client secret minimum length per allowed HS* alg – PLANNED

### Phase 2 – Governance, Assurance & Observability (Next)
Will start once: (a) audit writer + logout events + client JAR/JARM UI + minimum HS* secret policy are in place; (b) baseline metrics scaffold exists.

### Phase 3 – Advanced OAuth/OIDC & Access Control
(No change)

### Phase 4 – Compliance, Analytics & Future Readiness
(No change)

## 5. Immediate Sprint Backlog (Updated)
Re-ordered by urgency (security > correctness > governance > visibility):
1. Audit log writer + integrity hash implementation (append-only) – NOT STARTED
2. Full logout notifications (front + back channel event dispatch) – IN PROGRESS
3. Client-level JAR/JARM UI (JarMode/JarmMode/AllowedRequestObjectAlgs/RequireSignedRequestObject) – NEW / NOT STARTED
4. Dynamic client registration approval workflow + tests – IN PROGRESS
5. Symmetric client secret policy service (HS* min lengths + validation + admin warnings) – PLANNED
6. Expand tests: JAR replay (jti), oversize rejection, unsupported alg, JARM packaging validation – NOT STARTED
7. Metrics scaffolding (auth_requests_total, token_issuance_latency_seconds) – NOT STARTED
8. Audit events for JAR/JARM failures (auth.security) – PENDING
9. PAR enforcement logic for clients with Required mode – NOT STARTED
10. Consent expiration: include claim expansion invalidation – NOT STARTED
11. Discovery adaptation: dynamic request_object_signing_alg_values_supported (realm/system union with policy filtering) – PLANNED
12. JWE design spike (request object encryption strategy) – PENDING
13. UI regression test for Realm Defaults page (tabs render content) – NOT STARTED

## 6. Data Model Additions (Phase 1 & 1.5)
(Updated: Added guarded migration for realm default JAR/JARM columns – `RealmJarJarmDefaults`.)

## 7. Security Controls (Phase 1 Target State)
| Control | Minimum Implementation | Status |
|---------|------------------------|--------|
| Key Rotation | Scheduled job + overlapping JWKS | INITIAL COMPLETE |
| Client Secret Storage | Hash + metadata | BASELINE COMPLETE |
| Consent | Stored decisions + scope diffing | COMPLETE |
| Logout | Front/back channel notifications | PARTIAL |
| Audit | Append-only table + integrity hash | PENDING |
| Token Lifetimes | Realm + client overrides | COMPLETE |
| JAR | Signed request object; exp<=5m; mismatch rejection; replay (jti); size limit; alg allow-list | COMPLETE |
| JARM | Signed JWT authorization response (code+state+iss+aud+iat+exp) | COMPLETE (baseline) |
| Symmetric Secret Policy | Enforce algorithm-based minimum length (reject/ warn on HS384/512 if too short) | PLANNED |
| Realm JAR/JARM Defaults UI | Realm-level defaults configurable | COMPLETE |

## 8. Open Issues to Clarify
- Do we require distributed replay cache for multi-node before production? (Leaning: Phase 2 with Redis)
- Decide whether to auto-downgrade requested HS384/512 to HS256 when secret length insufficient, or hard fail. (Recommendation: HARD FAIL to prevent silent weakening.)
- Should discovery dynamically suppress HS384/512 if any configured client fails policy (global) or always advertise and rely on per-client rejection? (Recommendation: Advertise only algorithms globally enforced & policy-compliant to reduce negotiation confusion.)
- Should realm default AllowedRequestObjectAlgs feed dynamic discovery list (union of enabled algs) – risk of enumeration vs clarity. (Recommendation: Use curated allow-list from global + any realm-default that passes policy; redact if count=0.)

## 9. Acceptance Criteria Examples (Phase 1 & 1.5 Highlights)
- JAR: Oversized (> configured) rejected; missing jti when required rejected; replayed jti rejected.
- JARM: JWT response validated by client test harness; payload claims present; normal flow unaffected when disabled.
- Symmetric Secret Policy: Selecting HS384 requires client secret length >= 48 bytes; HS512 >= 64 bytes; HS256 >= 32 bytes. Rejections produce `invalid_client` or `invalid_request_object` with descriptive error.
- Realm Defaults UI: Updating JAR/JARM defaults persists and influences new clients unless overridden; page renders all tabs without blank content.

## 10. Risks & Mitigations
| Risk | Mitigation |
|------|------------|
| Replay cache not distributed | Introduce distributed cache (Redis) in Phase 2 before scale-out |
| Admin UI lagging for JAR/JARM config | Realm defaults UI done; prioritize client-level wiring next sprint |
| Weak symmetric secrets accepted for stronger HS* algs | Enforce length policy; block selection until rotated |
| Padding used in tests could mask production weakness | Disable padding outside test helpers; add validation layer |
| UI regression (empty tab content) due to RadzenTabs misconfiguration | Maintain `TabRenderMode.Server` + automated UI regression test |

## 11. Tracking & Metrics (Phase 2 Plan)
Add planned metrics: jar_requests_total{mode,outcome,alg,replay}; jarm_responses_total{mode,outcome}; secret_policy_violations_total{alg,outcome}; client_secret_rotation_events_total.

## 12. Next Steps (Actionable – Updated & Sequenced)
### A. Critical Path (Security + Integrity)
1. Implement audit writer + integrity hash chain (unblocks security posture & compliance narrative).
2. Complete logout notifications (front-channel frame + back-channel dispatch) with event audit entries.
3. Ship symmetric secret policy enforcement (validation service + UI warnings + documentation).

### B. Protocol Hardening Completion
4. Finish client-level JAR/JARM UI (persist + validation + integration tests).
5. Expand JAR/JARM negative/edge tests (replay, oversize, unsupported alg, JARM structure).
6. PAR Required mode enforcement (reject non-PAR requests with spec-aligned error).

### C. Observability Foundations
7. Introduce minimal metrics middleware (counter + histogram) and register OpenTelemetry exporters (no traces yet).
8. Emit audit events for JAR/JARM failures (category=auth.security, outcome codes).

### D. Governance & UX
9. Complete dynamic client registration approval workflow (state transitions + audit events).
10. Discovery adaptation for request object alg values (policy-filtered list).

### E. Forward-Looking Design
11. JWE request object encryption design spike (key negotiation, alg/enc matrix, migration path, metadata fields).
12. UI regression test harness addition for critical admin pages (Realm defaults + Client edit with JAR/JARM tabs).

### Sequencing Justification
- Audit + logout + secret policy close current Phase 1 risk items.
- JAR/JARM UI + tests finalize Phase 1.5 deliverables before expanding protocol scope.
- Metrics introduced early to measure adoption & error surfaces before Phase 2 scale-up.
- Governance (client approval) naturally follows once audit is reliable, ensuring traceability.

### Exit Criteria for Declaring Phase 1/1.5 COMPLETE
- All Critical Path (A) + Protocol Hardening Completion (B) tasks DONE.
- Metrics counters operational and visible (even if minimal) for JAR/JARM + auth/token endpoints.
- Dynamic client registration flow enforced and audited.

## 13. Assessment Summary (What To Do Next)
Immediate focus must shift to: (1) persisting trustworthy audit records; (2) closing logout event gap; (3) enforcing cryptographic hygiene for symmetric secrets. These three items elevate baseline trustworthiness and reduce remediation cost later. Parallel low-risk effort can begin on client-level JAR/JARM UI. Testing debt on JAR/JARM should be resolved before adding JWE complexity to avoid compounding unknowns.

---
Prepared for: MrWho Identity Platform
