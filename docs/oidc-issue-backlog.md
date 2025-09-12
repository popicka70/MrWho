# OIDC Platform Implementation Backlog

Generated: 2025-09-12 (updated after Items 1 & 2 progress)
Source: Enterprise Roadmap (Phase 1 & 1.5)

Legend:
- Status: TODO | IN PROGRESS | BLOCKED | DONE
- Priority: P0 (critical), P1 (high), P2 (normal), P3 (defer)
- Labels (suggested): security, oidc, audit, ui, tests, observability, governance, cryptography, design, infrastructure

---
## Index
1. Audit Log Writer & Integrity Chain (P0)
2. Correlation & Actor Resolution Middleware (P0)
3. Front-Channel Logout Implementation (P0)
4. Back-Channel Logout Dispatch Completion (P0)
5. Symmetric Secret Policy Enforcement (P0)
6. Client-Level JAR/JARM UI Wiring (P1)
7. JAR/JARM Negative & Edge Test Expansion (P1)
8. PAR Required Mode Enforcement (P1)
9. Dynamic Client Registration Approval Workflow Completion (P1)
10. Metrics Scaffolding (Phase 1 Scope) (P1)
11. Discovery Adaptation for Request Object Algs (P1)
12. JAR/JARM Audit Events (P1)
13. JWE Request Object Encryption Design Spike (P2)
14. UI Regression Test Harness (Admin Pages) (P2)
15. Logout Event Audit Integration (P1)

---
## 1. Audit Log Writer & Integrity Chain
Status: IN PROGRESS  Priority: P0  Labels: security,audit,backend
Depends On: —
Description:
Implement append-only audit persistence with cryptographic integrity chain.
Data model columns: Id (ULID), TimestampUtc, Category, Action, ActorType, ActorId, SubjectType, SubjectId, RealmId (nullable), CorrelationId, DataJson, PreviousHash, RecordHash, Version.
Integrity: RecordHash = SHA-256( canonical(JSON(ordered fields)) + PreviousHash + Version ).
Tasks:
- [x] Confirm / create EF entity (ULID)  (DB migration still to be generated/applied)
- [x] Implement canonical serializer (stable ordering; exclude RecordHash)
- [ ] Hash service abstraction (IIntegrityHashService) (currently inline SHA-256 implementation)
- [x] Scoped IAuditWriter (AuditIntegrityWriter) with WriteAsync(dto)
- [x] Correlation/actor context integration hook (via CorrelationMiddleware + accessor)
- [x] Verification service: full chain scan + latest head retrieval
- [x] Admin endpoint /health/audit-integrity (returns status summary)
- [x] Unit tests: hash link, tamper detection (performance test still pending <3ms target)
- [ ] Performance benchmark (<3ms per write locally)
Acceptance (pending items):
- Tampering triggers verification failure (DONE)
- At least 3 categories written in tests without chain break (basic chain test DONE; add multi-category test optional)

## 2. Correlation & Actor Resolution Middleware
Status: DONE  Priority: P0  Labels: infrastructure,audit
Depends On: 1 (optional but recommended)
Description:
Middleware to resolve/generate CorrelationId (header X-Correlation-Id). Provide ICorrelationContextAccessor. Resolve Actor (system/user/client) for audit.
Tasks:
- [x] Middleware implement & register early in pipeline
- [x] Add response header echo
- [x] Accessor service injectable (HttpContext.Items implementation)
- [x] Unit tests: preserves inbound; generates new when absent; user & client actor resolution
Acceptance:
- Present for all controller/page requests (implemented in Program pipeline)

## 3. Front-Channel Logout Implementation
Status: TODO  Priority: P0  Labels: oidc,logout,security
Depends On: 1 (audit events capture)
Description:
Implement OIDC front-channel logout (iframe/script). Store per-client front-channel logout URL metadata.
Tasks:
- [ ] Client metadata field + migration
- [ ] UI field (client edit) + validation (HTTPS required outside dev)
- [ ] EndSession page emits hidden iframes for each participating client (same user session)
- [ ] Include sid + iss (and optional client_id) as query params per spec
- [ ] Audit events (initiated, frontchannel.dispatch)
- [ ] Tests (bUnit / integration) verifying iframe generation
Acceptance:
- Multiple clients cause multiple iframes
- Absent URL: client skipped

## 4. Back-Channel Logout Dispatch Completion
Status: TODO  Priority: P0  Labels: oidc,logout,security,reliability
Depends On: 1
Description:
Send signed logout tokens to registered back-channel endpoints with retry policy.
Tasks:
- [ ] Complete JWT logout token builder (iss, sub, aud?, events, sid, iat)
- [ ] Endpoint registration metadata + UI
- [ ] Dispatch background job (queue + retry: e.g., 1m, 5m, 15m) with max attempts
- [ ] Outcome audit logging (success/failure + status code)
- [ ] Metrics hook placeholder (future)
Acceptance:
- Failure after max retries audited
- Valid token signature verified in test harness

## 5. Symmetric Secret Policy Enforcement (HS*)
Status: TODO  Priority: P0  Labels: security,cryptography
Depends On: 2
Description:
Enforce minimum lengths: HS256>=32B, HS384>=48B, HS512>=64B for client secrets & request object signing.
Tasks:
- [ ] Config object + defaults
- [ ] Validation service (ISymmetricSecretPolicy)
- [ ] Client create/update enforcement + friendly error
- [ ] JAR validation integration (reject invalid secret length for selected alg)
- [ ] UI warnings (inline + tooltip) + pre-save blocking
- [ ] Discovery filter: remove algs failing global enforcement
- [ ] Tests: each boundary + downgrade attempt
Acceptance:
- Attempt HS512 with 48B secret rejected
- Discovery omits HS512 after violation when no compliant clients

## 6. Client-Level JAR/JARM UI Wiring
Status: TODO  Priority: P1  Labels: ui,oidc
Depends On: 5
Description:
Expose JarMode, JarmMode, AllowedRequestObjectAlgs (multi), RequireSignedRequestObject in client edit form.
Tasks:
- [ ] Add fields to DTO + mapping
- [ ] Blazor form controls (RadzenFormField usage) + validation
- [ ] Persist & reload
- [ ] Integration test: change persists
- [ ] Guard: RequireSignedRequestObject => alg list non-empty
Acceptance:
- Changing JarMode=Required enforces signed request on next auth attempt

## 7. JAR/JARM Negative & Edge Tests
Status: TODO  Priority: P1  Labels: tests,security
Depends On: 5, 6
Description:
Add integration tests for replay (jti), oversize, unsupported/disallowed alg, expired, max skew edge, JARM JWT claim presence.
Tasks:
- [ ] Helper to craft custom request objects
- [ ] Replay test storing jti then reusing
- [ ] Oversize generation (size > configured limit)
- [ ] Unsupported alg (e.g., HS1024) & disallowed alg (valid but not in allow-list)
- [ ] Expired + near-exp boundary
- [ ] JARM JWT decode & signature verify
- [ ] Assertions ensure audit (when implemented) not duplicated
Acceptance:
- All negative scenarios return correct OAuth error codes

## 8. PAR Required Mode Enforcement
Status: TODO  Priority: P1  Labels: oidc,protocol
Depends On: 6
Description:
Reject non-PAR authorization attempts for clients with ParMode=Required.
Tasks:
- [ ] Authorization pipeline check (before consent)
- [ ] Error: invalid_request with description referencing PAR
- [ ] Tests: Required vs Optional vs Off
Acceptance:
- Non-PAR request for Required client fails early

## 9. Dynamic Client Registration Approval Workflow Completion
Status: IN PROGRESS  Priority: P1  Labels: governance,oidc,audit
Depends On: 1, 2
Description:
Implement Pending -> Approved|Rejected|Canceled states with audit events and enforcement.
Tasks:
- [ ] Persist status + optional rejection reason
- [ ] Admin approve/reject UI actions (async handlers)
- [ ] Token issuance block if not Approved
- [ ] Audit events for transitions
- [ ] Tests for blocked client & approval path
Acceptance:
- Pending client cannot obtain tokens

## 10. Metrics Scaffolding (Phase 1 Scope)
Status: TODO  Priority: P1  Labels: observability,metrics
Depends On: 7 (to emit outcomes), 5
Description:
Add OpenTelemetry metrics (counters + histogram) + minimal exporter (Prometheus or OTLP).
Metrics:
- auth_requests_total{outcome,jar_mode}
- jar_requests_total{outcome,alg,replay}
- jarm_responses_total{outcome}
- secret_policy_violations_total{alg,outcome}
- token_issuance_latency_seconds (histogram)
Tasks:
- [ ] Add OpenTelemetry.Extensions + configuration
- [ ] Middleware/instrumentation points
- [ ] Unit/integration test increments
Acceptance:
- Counter increments visible via metrics endpoint

## 11. Discovery Adaptation (request_object_signing_alg_values_supported)
Status: TODO  Priority: P1  Labels: oidc,discovery
Depends On: 5
Description:
Compute union of global allowed + realm defaults filtered by symmetric secret policy; omit if empty.
Tasks:
- [ ] Service computing set per realm
- [ ] Discovery document injection
- [ ] Tests for add/remove scenario
Acceptance:
- Removing last compliant HS algorithm removes it from discovery

## 12. JAR/JARM Audit Events
Status: TODO  Priority: P1  Labels: audit,security
Depends On: 1, 7
Description:
Emit jar.validation_failed, jarm.issued, jarm.failure with correlation & client id.
Tasks:
- [ ] Event definitions + constants
- [ ] Writer calls in existing validation / issuance code paths
- [ ] Tests asserting audit records presence
Acceptance:
- Replay violation logs jar.validation_failed(reason=replay)

## 13. JWE Request Object Encryption Design Spike
Status: TODO  Priority: P2  Labels: design,security
Depends On: 7
Description:
Produce design doc: alg/enc matrix, metadata fields, key acquisition, migration, threat model considerations.
Tasks:
- [ ] Evaluate required alg set (RSA-OAEP-256 + A256GCM etc.)
- [ ] Client metadata extension plan (request_object_encryption_alg / enc)
- [ ] Mixed sign+encrypt vs encrypt-only model decision
- [ ] Size impact estimates & compression consideration
- [ ] Risk & phased rollout plan
Acceptance:
- Approved doc stored in docs/jwe-design.md

## 14. UI Regression Test Harness (Admin Pages)
Status: TODO  Priority: P2  Labels: ui,tests
Depends On: 6
Description:
Playwright (or bUnit + JS interop) tests verifying critical admin forms render all tab content & fields.
Tasks:
- [ ] Test project config (Playwright / headless)
- [ ] Realm defaults page content assertions
- [ ] Client edit JAR/JARM tab field presence & state change
Acceptance:
- Removing a field causes failing test

## 15. Logout Event Audit Integration
Status: TODO  Priority: P1  Labels: audit,logout
Depends On: 3, 4, 1
Description:
Emit logout.initiated, logout.frontchannel.dispatch, logout.backchannel.dispatch (with client result codes array).
Tasks:
- [ ] Hook into end-session start
- [ ] Front-channel dispatch enumeration audit
- [ ] Back-channel aggregate result logging
- [ ] Tests verifying audit sequence
Acceptance:
- Single logout yields at least initiated + one dispatch record

---
## Cross-Cutting Guidelines
- Use dependency-injected IClock for time to simplify test skew & exp boundary cases.
- Prefer ULID for sortable IDs (microsecond precision) in audit chain.
- Ensure all async Blazor event handlers use async/await pattern (see copilot instructions).
- Radzen UI: Always wrap inputs with RadzenFormField; use Start slot for boolean controls.
- Testing: Provide builder utilities for crafting JWT/JAR variations; isolate crypto from scenario logic.
- Security: Harden error messages (no secret length leakage) while still descriptive ("HS512 secret length below policy minimum").

## Suggested Milestone Grouping
Milestone: Phase1-Security-Core -> Issues 1-5,15
Milestone: Phase1.5-UI-Hardening -> Issues 6-8,11,12
Milestone: Governance-Observability -> Issues 9-10
Milestone: Advanced-Design -> Issues 13-14

---
## Creation Checklist (When Opening GitHub Issues)
For each issue:
- Title = heading
- Body: copy section (Description, Tasks, Acceptance, Depends On)
- Apply labels per section
- Link dependency using issue numbers once created

---
## Next Step Proposal (Post Items 1 & 2 Progress)
Immediate priorities:
1. Finish remaining Item 1 gaps (migration + IIntegrityHashService + performance benchmark) – small, high value for audit assurance.
2. Begin Item 5 (Symmetric Secret Policy) – prerequisite for the large JAR/JARM & PAR feature chain (Items 6-8,11,12). Implement config + validator + enforcement + tests.
3. In parallel, start Item 3 (Front-Channel Logout) after migration for new client metadata so logout sequence & later Item 15 can be unblocked.

Rationale: Completing Item 5 early unlocks multiple P1 protocol hardening tasks; finishing Item 1 solidifies trust in subsequent audit events.

End of backlog.
