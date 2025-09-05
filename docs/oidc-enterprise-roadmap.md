# MrWho OIDC Enterprise Readiness Roadmap

Last updated: 2025-09-05

## 1. Purpose
Structured, phased plan to evolve the MrWho OpenID Connect / OAuth2 platform (OpenIddict-based) into an enterprise?grade identity and authorization service. Phases balance protocol completeness, security posture, governance, and operational excellence.

## 2. Current Implemented Capabilities (Baseline)
- Core grants: Authorization Code + PKCE (enforced), Client Credentials, Refresh Token (rolling in non-dev), Password (tests only).
- Endpoints: authorization, token, userinfo, revocation, introspection, end session, discovery.
- Realms (basic model) + per-realm default token lifetime fields (not yet enforced at issuance).
- Dynamic DB?backed client + scope management with synchronization to OpenIddict.
- Standard + custom scopes (api.read, api.write, mrwho.use, roles variants).
- Rate limiting (fixed window, IP based) for key endpoints.
- External IdP federation (dynamic OIDC provider registrations from DB).
- Back-channel logout service placeholder; logout endpoint (end session) exposed.
- Basic logging (no structured audit store) + seed users/clients/realms.
- Separation of client cookies (per client) and dynamic policy provider.
- Refresh token rotation (non-dev) enabled implicitly.

## 3. Gap Summary (What Is Missing vs Enterprise Targets)
| Category | Key Gaps |
|----------|----------|
| Protocol & Security | Device flow, dynamic client registration, PAR/JAR/JARM, token exchange, resource indicators, DPoP, mTLS, front/back?channel logout notifications, JWE, key rotation strategy, PoP tokens, reference tokens option |
| Identity & Claims | Consent UI + persistence, claim transformation/mapping policies (per realm/client), attribute release control, SCIM 2.0, groups/roles aggregation, self?service profile & session mgmt, realm claim isolation |
| Client & Governance | Secret hashing + rotation metadata, approval workflow, per-client lifetimes enforcement, soft delete/versioning, per-client rate limits/quotas, tenant (realm) isolation of keys & policies |
| Authentication Assurance | MFA (TOTP, WebAuthn/passkeys), step-up policies, adaptive/risk signals, password breach checks, session concurrency & idle revocation, device fingerprint & management UI |
| Observability & Ops | Structured audit/event store, OpenTelemetry metrics/traces, security event streaming (CAEP), health/readiness depth checks, SIEM export, config-as-code export/import, disaster recovery runbooks |
| Token & Session | Resource/audience negotiation (RFC 8707), CAE (continuous access evaluation) hooks, session revocation APIs, refresh token reuse detection logging, per-scope audience restrictions |
| Developer & Integration | Dynamic client registration with governance, sandbox tenants, scope catalog endpoint, Postman/SDK generation, config diff/rollback, test harness improvements (replay simulator) |
| Security & Compliance | GDPR export/delete workflows, PII encryption at rest, data retention policies, secret scanning, HSM/KMS for keys, FAPI (advanced security profile) readiness |
| Future Readiness | Passkey-first flows (WebAuthn resident keys), FAPI 2.0 baseline & advanced, GNAP path exploration |

## 4. Phased Roadmap
### Phase 1 – Core Protocol Hardening & Key Security (High Priority)
Goal: Close critical protocol/security gaps blocking production adoption.
- Add device authorization (RFC 8628) endpoints (device + verification) + rate limits.
- Implement dynamic client registration (protected; admin approval queue).
- Hash stored client secrets (PBKDF2/Argon2) + rotation metadata (Created, LastUsed, Expires, IsCompromised flags).
- Persistent signing & encryption keys (replace dev certs) + automated rotation framework (publish overlapping JWKS; retirement policy).
- Enforce per-realm/client token lifetimes during issuance.
- Front-channel + back-channel logout notification support (OIDC logout specs).
- Consent service (UI + storage) – baseline (remember/forget decisions, scope diffing).
- Structured audit log (append-only) for auth events, token issuance, admin changes.

### Phase 2 – Governance, Assurance & Observability
- MFA stack: TOTP + WebAuthn (attestation caching) + policy binding (per realm/client/scope sensitivity).
- Adaptive/risk signals (IP reputation, geo-impossible travel baseline, device novelty score).
- Policy-driven claim release (per client + scope whitelist + transformation rules).
- SCIM 2.0 (users + groups) provisioning endpoints with realm scoping.
- Per-client rate limits + quotas (token issuance, auth attempts) – move from IP-only.
- Config export/import (GitOps): realms, clients, scopes, policies (JSON schema + checksum).
- OpenTelemetry metrics (latency per grant, error taxonomy, token issuance counts) + tracing across request pipeline.
- Secret rotation workflow (admin UI + scheduled reminders).

### Phase 3 – Advanced OAuth/OIDC & Access Control
- PAR (RFC 9126), JAR, JARM for high-trust clients; toggle per client/realm.
- Token exchange (RFC 8693) for delegation/impersonation.
- Resource indicators (RFC 8707) + audience negotiation.
- Reference tokens (opaque) + introspection performance cache (distributed) option.
- DPoP + mTLS client auth (selected high-assurance clients).
- Continuous Access Evaluation (event push + revocation reasons) initial.
- Session & refresh token global revocation APIs + reuse detection logging.
- Group/role aggregation service (directory sync adapter abstraction).

### Phase 4 – Compliance, Analytics & Future Readiness
- GDPR workflows: export (subject data bundle) + delete (anonymize strategy) + retention policies.
- PII encryption at rest (field-level; keys via KMS/HSM) + key hierarchy design.
- Security Event streaming (CAEP) + SIEM integration connectors.
- FAPI baseline hardening (nonce enforcement auditing, PAR mandatory, JARM tokens, MTLS/DPoP for confidential clients).
- Passkey-first login UX + resident credential lifecycle management.
- Advanced analytics dashboards (conversion funnel, failure taxonomy clustering, anomaly detection).
- Policy versioning + rollback; diffable history for clients/realms.

## 5. Immediate Sprint Backlog (Suggested Sequence)
1. Persistent key material + rotation scaffolding (dual set publication, rollover job).
2. Client secret hashing + migration (+ admin UI to rotate).
3. Per-realm token lifetime enforcement middleware/service.
4. Device authorization flow implementation (endpoints + integration tests).
5. Consent persistence + basic UI + issuance pipeline hook.
6. Structured audit log store (EF table + lightweight writer + query API) + log critical events.
7. Logout notifications (front + back channel) + test coverage.

## 6. Data Model Additions (Phase 1)
- ClientSecretHistory: Id, ClientId, SecretHash, Algo, CreatedAt, ExpiresAt, LastUsedAt, Status.
- KeyMaterial: Id, Use (sig/enc), Kid, Algorithm, CreatedAt, ActivateAt, RetireAt, RevokedAt, Status, IsPrimary.
- Consent: Id, UserId, ClientId, GrantedScopes(json), CreatedAt, UpdatedAt, Version.
- AuditEvent: Id, TimestampUtc, Actor (User/Client/System), ActorId, Type, Category, Realm, CorrelationId, Data(json), Severity.

## 7. Security Controls (Phase 1 Target State)
| Control | Minimum Implementation |
|---------|------------------------|
| Key Rotation | Scheduled job + overlapping JWKS publication; retire old after grace period |
| Client Secret Storage | Hash (Argon2id preferred) + per-secret metadata + rotation API |
| Consent | Stored decisions; auto-expire on scope/claim expansion |
| Logout | Front + back channel events + admin UI session view |
| Audit | Append-only table + integrity hash (optional in Phase 1) |
| Token Lifetimes | Realm + client overrides applied centrally in issuance pipeline |

## 8. Open Issues to Clarify
- Multi-region deployment requirements (affects key replication strategy?).
- External directory sources (AD/LDAP/HR) priority for group synchronization.
- Minimal viable risk signals for adaptive auth (start with IP/geo?).
- Regulatory targets (GDPR only or also SOC2 / ISO / HIPAA?).

## 9. Acceptance Criteria Examples (Phase 1 Highlights)
- Device Flow: POST /connect/device returns device_code + user_code; polling token endpoint yields pending/slow_down/authorization_pending then tokens; tests cover positive + rate limit.
- Secret Hashing: Plain secrets migrated; no plaintext retrievable; verification passes existing clients; rotation invalidates prior secret after grace period.
- Key Rotation: New key published; tokens signed by new key after switch; old key validates existing tokens until retirement timestamp.
- Consent: First-time authorization prompts; subsequent requests without new scopes skip prompt; revoking consent removes stored grant and forces prompt.
- Audit: Creating client writes audit record (Type=client.create); fetching audit list by correlation ID returns expected sequence.

## 10. Risks & Mitigations
| Risk | Mitigation |
|------|------------|
| Feature creep delays hardening | Lock Phase 1 scope; defer advanced flows (PAR/JAR) to Phase 3 |
| Secret migration disruption | Dual-verify window: accept old plaintext until first hash write completes |
| Key rotation outage | Stage rotation in non-prod; smoke test issuance + validation before production cutover |
| Consent UX confusion | Provide clear diff list of newly requested scopes |

## 11. Tracking & Metrics (Introduce with Phase 2)
- Metric: auth_requests_total{grant_type, outcome}
- Metric: token_issuance_latency_seconds (histogram)
- Metric: refresh_token_reuse_detected_total
- Metric: consent_prompt_rate (prompts / authorizations)
- Metric: active_sessions{realm}

## 12. Next Steps (Actionable)
1. Approve Phase 1 scope list.
2. Create EF migrations for new tables (SecretHistory, KeyMaterial, Consent, AuditEvent).
3. Implement key management service abstraction (load, sign, rotate) + background rotation job skeleton.
4. Add issuance pipeline hook to enforce per-realm/client lifetimes.
5. Add device flow endpoints + tests.
6. Implement consent service + UI + issuance filter.
7. Add secret hashing migration + rotation endpoint.
8. Build audit writer + enrich existing critical operations.

---
Prepared for: MrWho Identity Platform
