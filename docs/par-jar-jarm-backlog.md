# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (UPDATED AFTER OPENIDDICT SOURCE REVIEW + PAR STRATEGY DECISION)
Owner: Identity Platform
Last Updated: UTC {{DATE}}
Target Version: Phased (v1.1 – v1.4)

## Progress Snapshot (Sprint 1 Ongoing)
- Completed (✅):
  - PJ4 (IJarValidationService implemented; unified validator + DI)
  - PJ5 (Alg + size enforcement including per-client allowed alg list; default RS256/HS256)
  - PJ6 (Lifetime & skew: exp window, iat/nbf sanity checks)
  - PJ45 (Middleware JAR expansion removed; stub left for mode enforcement only)
  - PJ37 (Partial) – CustomExclusive early extract handler preempts built-in by stripping `request` param after validation
  - Tests updated: Jar oversize + invalid alg=none (part of PJ24 hardening)
- In Progress (🛠):
  - PJ7 (Issuer/Audience binding not yet enforced) 
  - PJ24 (Need explicit RS256 path test; current HS256 test passes; add RS case)
  - PJ25 (PAR+JAR combined path verification pending; relies on native PAR only in Phase 1)
  - PJ19 (Error catalog document not yet drafted)
- Upcoming (🎯 next sprint or remainder Sprint 1): PJ7, PJ24 (RS test), PJ25, PJ19, finalize PJ37 tracing proof.

(Original backlog follows; statuses will be updated incrementally.)

## 0. Context Snapshot (Current State)
- PAR: Relying on OpenIddict native pushed authorization endpoint (built-in persistence). Custom `PushedAuthorizationRequest` entity present but NOT wired into live flow.
- PAR Strategy DECIDED: Adopt Native+Augmentation ("Adapter") approach (reuse native endpoint + metadata adjunct for hash/reuse/consumption markers). CustomFull deferred unless new requirements emerge.
- JAR: Central validator & early extract handler now active (PJ4/5/6/37 partial). Legacy middleware expansion removed (PJ45).
- JARM: Custom event handlers (`JarJarmServerEventHandlers`) implement early normalization + signed JWT wrapping of responses. Middleware duplication scheduled for removal (PJ46) – unchanged this sprint.
- Mode flags (ParMode/JarMode/JarmMode): Basic JarMode=Required enforcement still in middleware stub; future consolidation pending.
- Replay: jti replay logic present inside validator (RequireJti true) but full PJ17 scope (metrics + negative test) deferred to Phase 2.
- Discovery: Still static; gating (PJ42) pending.
- Risk: Built-in request object handlers neutralized when JarHandlerMode=CustomExclusive.

## 1. Objectives (Refined)
(unchanged except PAR decision finalized)

## 2. High-Level Epics (Updated)
| Epic | Title | Goal | Priority |
|------|-------|------|----------|
| E1 | Middleware & Routing Layer | Minimize surface; retire ad‑hoc JAR expansion | High |
| E2 | JAR Validation Service | Single authoritative validator (preempts built-in) | High |
| E3 | PAR Adapter (Native+Augmentation) | Hash/reuse/consumption over native store | High |
| E4 | JARM Packaging | Spec-compliant response JWTs | Medium |
| E5 | Mode Enforcement | Reliable Required/Optional enforcement | High |
| E6 | Security Hardening | Replay, limits, conflict detection | High |
| E7 | Migration & Cleanup | Remove dead code / entities | Medium |
| E8 | Test Suite Expansion | Coverage & regression safety | High |
| E9 | Telemetry & Observability | Metrics, logs, health | Medium |
| E10 | Documentation & DX | Guidance & migration | Medium |
| E11 | OpenIddict Integration Control | Handler suppression & ordering | High |

## 3. Detailed Backlog (Amended + New Stories)
### Epic E1 – Middleware & Routing
| ID | Story | Description | Acceptance Criteria | Status |
|----|-------|-------------|---------------------|--------|
| PJ1 | Retire custom PAR resolution | No custom DB lookup when Adapter mode active | (a) No middleware `request_uri` DB usage in Native/Adapter; (b) Tests pass | Pending |
| PJ2 | Parameter merge precedence | Ensure JAR claims override query; detect mismatches | (a) Conflict => RFC error; tests | Pending |
| PJ45 | Remove middleware JAR expansion | Shift to event handlers | (a) Middleware no longer touches `request`; (b) `_jar_validated=1` added by handler | ✅ Done |
| PJ46 | Response_mode normalization consolidation | Event handlers only | (a) Middleware no longer rewrites response_mode | Pending |

### Epic E2 – JAR Validation Service
| ID | Story | Description | Acceptance Criteria | Status |
|----|-------|-------------|---------------------|--------|
| PJ4 | Create `IJarValidationService` | Decode + validate + map parameters | Central service only | ✅ Done |
| PJ5 | Alg / size enforcement | Per-client alg + max bytes | Rejections implemented | ✅ Done |
| PJ6 | Lifetime & skew rules | exp/iat/nbf policy | Tests (to add) | ✅ Impl (tests pending) |
| PJ7 | Iss/Aud/Client binding | issuer=client_id; audience=server | Rejection on mismatch | 🛠 In Progress (not enforced yet) |
| PJ40 | Query vs request conflict detection | Critical param mismatch | Error issued | Pending |
| PJ41 | Claim & length limits | Limit count/value length | Error issued | Pending |
| PJ37 | Built-in handler preemption | Suppress built-ins | No double validation | Partial (needs trace test) |
| PJ38 | Extract stage integration | Early validation & merge | `_jar_validated=1` sentinel | ✅ Done |
| PJ17 | jti replay cache | Replay prevention | Second use fails + tests | Phase 2 |

### Epic E3 – PAR Adapter (Native+Augmentation)
(unchanged; all Pending / Phase 2)

### Epic E4 – JARM Packaging
(unchanged)

### Epic E5 – Mode Enforcement
(unchanged; current middleware stub handles JarMode=Required basic)

### Epic E6 – Security Hardening
(unchanged; PJ19 Pending)

### Epic E7 – Migration & Cleanup
(unchanged)

### Epic E8 – Testing (Selected Sprint 1 subset)
| ID | Story | Scope | Status |
|----|-------|-------|--------|
| PJ24 | Direct JAR happy path | HS256 done; add RS256 test | Partial |
| PJ25 | PAR+JAR combined path | End-to-end precedence | Pending |
| PJ26 | Required mode failures | Negative matrix | Pending |
| PJ27 | Replay tests | jti & request_uri | Phase 2 |
| PJ29 | Fuzz / malformed inputs | Robustness | Phase 2 |
| PJ46 | Validator perf baseline | Benchmark + report | Phase 4 |
| PJ52 | PAR reuse test | Duplicate within window | Phase 2 |
| PJ53 | PAR single-use rejection | Second authorize attempt | Phase 2 |

### Epics E9–E11
(No change yet; metrics & discovery gating pending future phases.)

## 4. Phased Delivery Plan (Updated for PAR Adapter)
| Phase | Scope | Exit Criteria |
|-------|-------|--------------|
| Phase 1 | JAR core (PJ4–PJ7 partial), preemption (PJ37 partial), remove middleware expansion (PJ45), initial tests (PJ24 HS path), error catalog draft (PJ19). | Central JAR validation active; legacy expansion removed; baseline tests pass. |
| Phase 2 | PAR Adapter core (PJ47–PJ50, PJ51, PJ52, PJ53), JAR replay & limits (PJ17, PJ40, PJ41), negative tests (PJ26, PJ27, PJ29), metrics (PJ30) | Reuse + single-use + conflict/limits operational; expanded tests green. |
| Phase 3 | JARM (PJ11–PJ13), PAR required (PJ14), discovery gating (PJ42), cleanup (PJ43 staged), health (PJ31, PJ32), docs (PJ33–PJ35) | JARM prod-ready; adaptive metadata; docs published. |
| Phase 4 | Final cleanup (PJ21–PJ23), migration guide (PJ36), perf baseline (PJ46), legacy PAR entity decision | Migration & performance goals met. |

## 5. Risk Register (Updated)
(unchanged; progress note: dual validator risk mitigated by early removal of `request` parameter.)

## 6. Config & Flags (Expanded)
(No change – implementation: JarHandlerMode=CustomExclusive active.)

## 7. Non-Goals (Explicit)
(unchanged)

## 8. Acceptance Gate (Phase 3)
(Add requirement: Iss/Aud enforcement tests for PJ7 must be present.)

## 9. Immediate Next Actions (Sprint 1 – Remaining)
1. PJ7 – Enforce issuer==client_id & aud server value; add tests.
2. PJ24 – Add RS256 direct happy path test.
3. PJ25 – Add PAR+JAR combined path test (ensure `_jar_validated` sentinel set & precedence logic holds).
4. PJ19 – Draft error catalog (initial markdown scaffold).
5. PJ37 – Add trace/log assertion test proving built-in request object handler not invoked.
6. Prepare placeholders for PJ40/PJ41 (specify config keys) without enabling enforcement.

## 10. Tracking & Mapping
(unchanged – mark completed stories with ✅ in issues.)

## 11. OpenIddict Source Assessment Summary
(Updated: Early extract handler successfully removes `request` parameter preventing downstream duplication.)

---
Backlog annotated with Sprint 1 progress.
