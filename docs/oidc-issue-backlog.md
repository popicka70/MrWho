# OIDC Platform Implementation Backlog

Generated: 2025-09-12 (updated after Items 1,2 & 3 completion + Item 5 near-complete)
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
Status: DONE  Priority: P0  Labels: security,audit,backend
Depends On: —
Description:
Append-only audit persistence with cryptographic integrity chain.
Data model columns: Id (ULID), TimestampUtc, Category, Action, ActorType, ActorId, SubjectType, SubjectId, RealmId (nullable), CorrelationId, DataJson, PreviousHash, RecordHash, Version.
Integrity: RecordHash = SHA-256( canonical(JSON(ordered fields)) + PreviousHash + Version ).
Tasks:
- [x] Confirm / create EF entity + migration (ULID)
- [x] Implement canonical serializer (stable ordering; exclude RecordHash)
- [x] Hash service abstraction (IIntegrityHashService)
- [x] Scoped writer (AuditIntegrityWriter) with WriteAsync(dto)
- [x] Correlation/actor context integration hook
- [x] Verification service (chain scan + head retrieval)
- [x] Admin endpoint /health/audit-integrity
- [x] Unit tests: chain, tamper detection
- [x] Performance benchmark (<3ms per write locally)
Optional Enhancements:
- Multi-category chain test (not required for acceptance)
- Periodic integrity verification metrics emission (future)
Acceptance: Met

## 2. Correlation & Actor Resolution Middleware
Status: DONE  Priority: P0  Labels: infrastructure,audit
Depends On: 1 (optional but recommended)
Description:
Middleware to resolve/generate CorrelationId (header X-Correlation-Id) and actor (system/user/client) with injectable accessor.
Tasks:
- [x] Middleware implement & register early
- [x] Response header echo
- [x] Accessor service (HttpContext.Items based)
- [x] Unit tests (inbound preserve, generate, user & client actors)
Acceptance: Met

## 3. Front-Channel Logout Implementation
Status: DONE  Priority: P0  Labels: oidc,logout,security,audit,tests
Depends On: 1
Description:
OIDC front-channel logout (iframe) enumeration with audit + tests.
Tasks:
- [x] Client metadata field + migration (FrontChannelLogoutUri)
- [x] UI field (client edit) + validation (HTTPS required outside dev)
- [x] EndSession/LoggedOut page emits hidden iframes for each participating client (same user session)
- [x] Include sid + iss + client_id query params
- [x] Audit events (logout.initiated, logout.frontchannel.dispatch)
- [x] Tests verifying iframe generation (direct + OIDC end-session path)
Acceptance: Met
Notes:
- Session-safe access guards added (no session configured scenario).
- sid issued during dynamic client sign-in when absent.

## 4. Back-Channel Logout Dispatch Completion
Status: IN PROGRESS  Priority: P0  Labels: oidc,logout,security,reliability,audit
Depends On: 1
Description:
Send signed logout tokens to registered back-channel endpoints with retry policy.
Tasks:
- [x] JWT logout token builder (iss, sub, aud, events, sid, iat)
- [x] Endpoint registration metadata + UI (BackChannelLogoutUri + session required field present in client edit page)
- [x] Outcome audit logging (success/failure/timeout/error/skip, exhaustion placeholder)
- [x] Background dispatch single-attempt path
- [x] Retry scheduler (1m,5m,15m backoff) wiring + scheduling hooks
- [ ] Retry attempt outcome audits (per-attempt success/failure) & terminal aggregated event
- [ ] Max attempts exhaustion audit (currently basic exhausted event logged only on schedule prevention; aggregate summary still pending)
- [ ] Metrics hook placeholder (counter: mrwho_logout_backchannel_attempts_total, mrwho_logout_backchannel_failures_total)
- [ ] Unit tests: schedule on failure, no schedule on success, exhaustion path (mock scheduler)
Acceptance (remaining):
- Failure after max retries audited with aggregated summary; signature validated in tests

---
## Updated Next Step Proposal (Item 4 Ongoing)
Immediate execution order:
1. Add unit tests for BackChannelLogoutService (failure -> schedules retry, success -> no schedule).
2. Extend retry scheduler to emit per-attempt audit (backchannel.retry.attempt) and final aggregate (backchannel.retry.result).
3. Add metrics counters (attempts/failures) + placeholder registration (no exporter yet).
4. Exhaustion test (simulate attempts reaching max) verifying aggregate audit event.
5. Then begin Item 6 DTO + basic Blazor UI wiring.

## 5. Symmetric Secret Policy Enforcement (HS*)
Status: DONE  Priority: P0  Labels: security,cryptography
Depends On: 2
Description:
Minimum lengths: HS256>=32B, HS384>=48B, HS512>=64B for client secrets & request object signing.
Tasks:
- [x] Config object + defaults (`SymmetricSecretPolicyOptions`)
- [x] Validation service (ISymmetricSecretPolicy + implementation)
- [x] Client create/update enforcement (API returns validation problem)
- [x] JAR validation integration (middleware rejects below-policy secret; redaction marker skip path)
- [x] UI warnings + pre-save blocking (Blazor client edit validation)
- [x] Discovery filter (dynamic removal of HS* when not required by any JAR-capable client)
- [x] Tests: boundary lengths (31/32, 47/48, 63/64) & downgrade attempt
- [x] Discovery omission test (no HS384/HS512 when no clients imply them)
- [x] Documentation snippet (admin guide) explaining secret rotation & required lengths (`docs/admin-symmetric-secret-policy.md`)
Acceptance: Met
Notes: Dynamic discovery ensures least-privilege alg advertisement.

## 6. Client-Level JAR/JARM UI Wiring
Status: TODO  Priority: P1  Labels: ui,oidc
Depends On: 5
Description:
Expose JarMode, JarmMode, AllowedRequestObjectAlgs, RequireSignedRequestObject.
Tasks:
- [ ] DTO + mapping
- [ ] Blazor form controls (RadzenFormField) + validation
- [ ] Persist & reload
- [ ] Integration test
- [ ] Guard: RequireSignedRequestObject => alg list non-empty
Acceptance:
- JarMode=Required enforces signed request

## 7. JAR/JARM Negative & Edge Tests
Status: TODO  Priority: P1  Labels: tests,security
Depends On: 5, 6
Description:
Replay, oversize, unsupported/disallowed alg, expired, skew boundary, JARM claims.
Tasks:
- [ ] Request object crafting helper
- [ ] Replay test (jti reuse)
- [ ] Oversize payload
- [ ] Unsupported / disallowed alg
- [ ] Expired + near-exp boundary
- [ ] JARM JWT decode & verify
- [ ] Audit duplication assertions
Acceptance:
- All scenarios yield correct OAuth errors

## 8. PAR Required Mode Enforcement
Status: TODO  Priority: P1  Labels: oidc,protocol
Depends On: 6
Description:
Reject non-PAR authorization when ParMode=Required.
Tasks:
- [ ] Pipeline check (pre-consent)
- [ ] Error: invalid_request referencing PAR
- [ ] Tests (Required vs Optional vs Off)
Acceptance:
- Non-PAR for Required client fails early

## 9. Dynamic Client Registration Approval Workflow Completion
Status: IN PROGRESS  Priority: P1  Labels: governance,oidc,audit
Depends On: 1, 2
Tasks:
- [ ] Persist status + rejection reason
- [ ] Admin approve/reject UI
- [ ] Token issuance block if not Approved
- [ ] Transition audit events
- [ ] Tests (blocked + approval path)
Acceptance:
- Pending client cannot obtain tokens

## 10. Metrics Scaffolding (Phase 1 Scope)
Status: TODO  Priority: P1  Labels: observability,metrics
Depends On: 7, 5
Tasks:
- [ ] Add OpenTelemetry + exporter
- [ ] Instrumentation points
- [ ] Counter & histogram tests
Acceptance:
- Metrics exposed & increment

## 11. Discovery Adaptation (request_object_signing_alg_values_supported)
Status: TODO  Priority: P1  Labels: oidc,discovery
Depends On: 5
Tasks:
- [ ] Per-realm alg service
- [ ] Discovery injection
- [ ] Add/remove tests
Acceptance:
- Removing last compliant HS alg removes set

## 12. JAR/JARM Audit Events
Status: TODO  Priority: P1  Labels: audit,security
Depends On: 1, 7
Tasks:
- [ ] Event constants
- [ ] Validation/issuance writer hooks
- [ ] Tests (replay -> jar.validation_failed(reason=replay))
Acceptance:
- Audit events emitted with correlation & client id

## 13. JWE Request Object Encryption Design Spike
Status: TODO  Priority: P2  Labels: design,security
Depends On: 7
Tasks:
- [ ] Alg/enc matrix
- [ ] Metadata plan
- [ ] Sign+encrypt vs encrypt-only decision
- [ ] Size & compression analysis
- [ ] Risk & phased rollout plan
Acceptance:
- Design doc stored at docs/jwe-design.md

## 14. UI Regression Test Harness (Admin Pages)
Status: TODO  Priority: P2  Labels: ui,tests
Depends On: 6
Tasks:
- [ ] Playwright/bUnit harness
- [ ] Realm defaults assertions
- [ ] Client edit JAR/JARM tab tests
Acceptance:
- Field removal breaks test

## 15. Logout Event Audit Integration
Status: TODO  Priority: P1  Labels: audit,logout
Depends On: 3, 4, 1
Tasks:
- [ ] Hook into end-session start
- [ ] Front-channel enumeration audit
- [ ] Back-channel aggregate result audit
- [ ] Sequence tests
Acceptance:
- Single logout => initiated + at least one dispatch event

---
## Cross-Cutting Guidelines
- Use IClock for time abstraction.
- Prefer ULID IDs for chain ordering.
- Async Blazor event handlers must use async/await.
- Radzen inputs always wrapped in RadzenFormField; boolean controls in Start slot.
- Provide builders for crafting JWT/JAR variations in tests.
- Harden error messages (no secret length leakage).

## Suggested Milestone Grouping
Milestone: Phase1-Security-Core -> Issues 1-5,15
Milestone: Phase1.5-UI-Hardening -> Issues 6-8,11,12
Milestone: Governance-Observability -> Issues 9-10
Milestone: Advanced-Design -> Issues 13-14

---
## Creation Checklist (When Opening GitHub Issues)
- Title = heading
- Body = section (Description, Tasks, Acceptance, Depends On)
- Apply labels
- Link dependencies

---
