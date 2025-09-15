# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (UPDATED AFTER OPENIDDICT SOURCE REVIEW + PAR STRATEGY DECISION)
Owner: Identity Platform
Last Updated: UTC {{DATE}}
Target Version: Phased (v1.1 – v1.4)

## 0. Context Snapshot (Current State)
- PAR: Relying on OpenIddict native pushed authorization endpoint (built-in persistence). Custom `PushedAuthorizationRequest` entity present but NOT wired into live flow.
- PAR Strategy DECIDED: Adopt Native+Augmentation ("Adapter") approach (reuse native endpoint + metadata adjunct for hash/reuse/consumption markers). CustomFull deferred unless new requirements emerge.
- JAR: Partial custom validation/expansion via `JarRequestExpansionMiddleware` (direct requests only). Will be replaced by early event handlers + `IJarValidationService` (PJ4/37/38/45).
- JARM: Custom event handlers (`JarJarmServerEventHandlers`) implement early normalization + signed JWT wrapping of responses. Middleware duplication scheduled for removal (PJ46).
- Mode flags (ParMode/JarMode/JarmMode): Enforcement partially present; PAR required detection unreliable without explicit resolution marker (to be added PJ50).
- Replay: In-memory jti cache abstraction exists; JAR validator integration for replay scheduled Phase 2 (PJ17).
- Discovery: Currently always advertises request/request_uri + jwt response_mode; will gate later (PJ42).
- Risk: Interference between OpenIddict internal request object handlers and custom logic if not preempted (JarHandlerMode=CustomExclusive, PJ37).

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
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ1 | Retire custom PAR resolution | No custom DB lookup when Adapter mode active | (a) No middleware `request_uri` DB usage in Native/Adapter; (b) Tests pass |
| PJ2 | Parameter merge precedence | Ensure JAR claims override query; detect mismatches | (a) Conflict => RFC error; tests |
| PJ45 | Remove middleware JAR expansion | Shift to event handlers | (a) Middleware no longer touches `request`; (b) `_jar_validated=1` added by handler |
| PJ46 | Response_mode normalization consolidation | Event handlers only | (a) Middleware no longer rewrites response_mode |

### Epic E2 – JAR Validation Service
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ4 | Create `IJarValidationService` | Decode + validate + map parameters (wrap existing validator) | (a) Only service used by handlers |
| PJ5 | Alg / size enforcement | Enforce per-client alg + max bytes | (a) Oversize/alg rejected |
| PJ6 | Lifetime & skew rules | exp/iat/nbf policy | (a) Exp window & iat skew tests |
| PJ7 | Iss/Aud/Client binding | issuer=client_id; audience=server | (a) Mismatch rejected |
| PJ40 | Query vs request conflict detection | Compare critical params | (a) Conflict error code |
| PJ41 | Claim & length limits | Max claims + per-value length | (a) Violations rejected |
| PJ37 | Built-in handler preemption | CustomExclusive mode removes/dodges native request object handlers | (a) Trace shows no built-in validation |
| PJ38 | Extract stage integration | Early validation & merge | (a) `_jar_validated=1` sentinel |
| PJ17 | jti replay cache | Replay prevention | (a) Second use fails |

### Epic E3 – PAR Adapter (Native+Augmentation)
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ39 | Strategy ADR (DONE) | Record decision Native+Augmentation | (a) ADR committed |
| PJ47 | `ParRequestMeta` entity | Adjunct metadata (hash/reuse/consumption) | (a) Migration created; table present |
| PJ48 | PAR push capture handler | Hash canonical params; dedupe reuse | (a) Reused URI returned; metric tagged reused |
| PJ49 | Authorize consumption handler | Mark consumed; enforce single-use if configured | (a) Second use -> invalid_request_uri when single-use |
| PJ50 | PAR resolution marker | Set `_par_resolved=1` + transaction flag | (a) Mode enforcement sees marker |
| PJ51 | PAR metrics | par_requests_total (new/reused), par_reuse_hits_total | (a) Counters visible |
| PJ8 | Hash + dedupe semantics | (Covered by PJ48) | (Merged) |
| PJ9 | Consumption policy | (Covered by PJ49) | (Merged) |
| PJ10 | Expiry scavenger | Background cleanup (optional) | (a) Removed rows metric |
| PJ44 | Native reuse integration | Use native store + meta | (a) All adapter tests green |

### Epic E4 – JARM Packaging
(unchanged)

### Epic E5 – Mode Enforcement
(unchanged; PAR required relies on PJ50 marker)

### Epic E6 – Security Hardening
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ18 | Audit logging | Accept/reject decisions | (a) Structured entries |
| PJ19 | Structured error codes | Error catalog | (a) Catalog file committed |
| PJ20 | Anti-bloat protections | Via PJ41 + JarMaxBytes | (a) See PJ41 |
| PJ43 | Remove obsolete PAR entity | Drop legacy table after migration | (a) Migration + doc updated |

### Epic E7 – Migration & Cleanup
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ21 | Remove unused placeholder code | Delete superseded classes | (a) No dead code |
| PJ22 | Schema migration review | Indexes for meta table | (a) ADR + applied |
| PJ23 | Config consolidation | `OidcAdvancedOptions` central | (a) Options class bound |
| PJ43 | Remove obsolete PAR entity | (Linked) | (a) Completed post rollout |

### Epic E8 – Testing
(Add PAR adapter tests)
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ24 | Direct JAR happy path | RS256 + HS256 | (a) Green |
| PJ25 | PAR+JAR combined path | End-to-end merge | (a) Precedence OK |
| PJ26 | Required mode failures | Negative matrix | (a) Error codes |
| PJ27 | Replay tests | jti & request_uri | (a) Rejections |
| PJ29 | Fuzz / malformed inputs | Robustness | (a) No crashes |
| PJ46 | Validator performance baseline | Throughput/latency | (a) Report |
| PJ52 | PAR reuse test | Submit duplicate within window | (a) Same request_uri |
| PJ53 | PAR single-use rejection test | Second authorize attempt | (a) 400 invalid_request_uri |

### Epic E9 – Telemetry & Observability
(Add PAR metrics story already PJ51)

### Epic E10 – Documentation & DX
(unchanged, add PAR Adapter notes to dev guide later)

### Epic E11 – OpenIddict Integration Control
(unchanged)

## 4. Phased Delivery Plan (Updated for PAR Adapter)
| Phase | Scope | Exit Criteria |
|-------|-------|--------------|
| Phase 1 | JAR core (PJ4–PJ7), handler preemption (partial PJ37), remove middleware expansion (PJ45), initial tests (PJ24, PJ25), error catalog draft (PJ19). PAR stays Native (no adapter metadata live). | Central JAR validation working; middleware dormant; tests green. |
| Phase 2 | PAR Adapter core (PJ47–PJ50, PJ51, PJ52, PJ53), JAR replay & limits (PJ17, PJ40, PJ41), negative tests (PJ26, PJ27, PJ29), metrics (PJ30) | Reuse + single-use operational; conflict/limit enforcement active. |
| Phase 3 | JARM (PJ11–PJ13), PAR required enforcement (PJ14), discovery gating (PJ42), cleanup (PJ43 staged), health endpoints (PJ31, PJ32), docs (PJ33–PJ35) | JARM prod-ready; adaptive discovery; docs published. |
| Phase 4 | Final cleanup (PJ21–PJ23), migration guide (PJ36), perf baseline (PJ46), decide on legacy PAR entity removal | Migration documented; performance targets recorded. |

## 5. Risk Register (Updated)
(unchanged; add below)
| Risk | Impact | Mitigation |
|------|--------|------------|
| PAR meta drift vs native store | Inconsistent consumption status | Always treat native store as source-of-truth; meta only augments |
| Hash canonicalization bugs | False reuse or misses | Deterministic sorted key JSON + test vectors |

## 6. Config & Flags (Expanded)
(Add PAR adapter specifics)
| Name | Values | Phase | Notes |
|------|--------|-------|-------|
| ParPipelineMode | Native | Adapter | CustomFull | 2 | Adapter activates meta handlers |
| ParSingleUseDefault | bool | 2 | Default consumption policy |
| ParReuseWindowSeconds | int | 2 | Dedupe window (0 disables) |
| ParAdapterEnabled (alias) | bool | 2 | Convenience toggle (derived) |
| JarHandlerMode | BuiltIn | CustomExclusive | 1 | Preempt built-ins |
| (others) | ... | ... | As listed earlier |

## 7. Non-Goals (Explicit)
(unchanged)

## 8. Acceptance Gate (Phase 3)
(unchanged + PAR adapter tests present)

## 9. Immediate Next Actions (Sprint 1 – Finalized)
1. PJ4 – Introduce `IJarValidationService` (wrap existing validator) + update DI + new OpenIddict extract handler.
2. PJ5 – Enforce alg + size via options + per-client AllowedRequestObjectAlgs.
3. PJ6 – Lifetime & skew validation central (remove partial logic from middleware).
4. PJ45 – Strip JAR expansion from middleware (leave temporary mode enforcement if still needed).
5. PJ37 – Implement `JarHandlerMode=CustomExclusive` (remove/neutralize built-in request object processing by clearing `request` param after validation).
6. PJ24 – Update direct JAR tests to assert `_jar_validated` sentinel not required externally but flow succeeds.
7. PJ25 – Ensure PAR+JAR path still works (JAR validated after native PAR resolution).
8. PJ19 – Draft error catalog (include codes: invalid_request_object_size, invalid_request_object_alg, invalid_request_object_conflict, invalid_request_object_claims, invalid_request_object_replay, invalid_request_uri_reuse_policy, etc.).

## 10. Tracking & Mapping
(unchanged – mark PJ39 DONE when ADR committed)

## 11. OpenIddict Source Assessment Summary
(Add note) – Adapter relies on push/authorize events; no changes to OpenIddict internal storage required.

---
Backlog updated to reflect Native+Augmentation PAR strategy.
