# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (UPDATED AFTER OPENIDDICT SOURCE REVIEW)
Owner: Identity Platform
Last Updated: UTC {{DATE}}
Target Version: Phased (v1.1 – v1.4)

## 0. Context Snapshot (Current State)
- PAR: Relying on OpenIddict native pushed authorization endpoint (built-in persistence). Custom `PushedAuthorizationRequest` entity present but NOT wired into live flow.
- JAR: Partial custom validation/expansion via `JarRequestExpansionMiddleware` (direct requests only). Mixed concerns (validation + merge) + potential double-processing risk with OpenIddict internal handlers.
- JARM: Custom event handlers (`JarJarmServerEventHandlers`) implement early normalization + signed JWT wrapping of responses. Middleware also normalizes `response_mode=jwt` (duplication).
- Mode flags (ParMode/JarMode/JarmMode): Enforcement partially present, PAR required detection unreliable when relying solely on built-in store.
- Replay: In-memory jti cache abstraction exists (not yet integrated into unified validator service path for JAR or JARM response tokens).
- Discovery: Custom augmentation always advertises `request` & `request_uri` support even when features partially implemented.
- Risk: Interference between OpenIddict internal request object handlers and custom middleware if both act on `request` / `request_uri`.

## 1. Objectives (Refined)
1. Provide a self-contained custom JAR validation pipeline that cleanly replaces (or preempts) OpenIddict’s built-in request object processing (no double parsing / conflicting errors).
2. Cleanly reuse OpenIddict native PAR storage when sufficient; introduce adapter only if advanced semantics (hash dedupe, multi-use policy) required.
3. Centralize JAR validation (alg whitelist, size, exp/iat/nbf, iss/aud, jti replay, param conflict detection, claim/length limits, integrity hash) behind `IJarValidationService` invoked at earliest feasible server event stage.
4. Implement JARM fully (success + error wrapping) strictly in event handlers (remove middleware duplication) with deterministic `kid` emission.
5. Enforce per-client modes (Disabled / Optional / Required) with reliable detection of PAR usage (native or custom) + clear error taxonomy.
6. Eliminate obsolete custom middleware responsibilities after migration (least surface area at authorize endpoint).
7. Provide robust negative, replay, fuzz and performance test coverage.
8. Adaptive discovery metadata (only advertise what is actually enabled/configured).

## 2. High-Level Epics (Updated)
| Epic | Title | Goal | Priority |
|------|-------|------|----------|
| E1 | Middleware & Routing Layer | Minimize surface; retire ad?hoc JAR expansion | High |
| E2 | JAR Validation Service | Single authoritative validator (preempts built-in) | High |
| E3 | PAR Store Strategy | Decide reuse vs adapter vs custom | High |
| E4 | JARM Packaging | Finalize spec-compliant response JWTs | Medium |
| E5 | Mode Enforcement | Reliable Required/Optional enforcement | High |
| E6 | Security Hardening | Replay, limits, conflict detection | High |
| E7 | Migration & Cleanup | Remove dead code / entities | Medium |
| E8 | Test Suite Expansion | Full coverage & regression safety | High |
| E9 | Telemetry & Observability | Metrics, logs, health | Medium |
| E10 | Documentation & DX | Guidance & migration | Medium |
| E11 | OpenIddict Integration Control | Handler suppression & ordering | High |

## 3. Detailed Backlog (Amended + New Stories)
### Epic E1 – Middleware & Routing
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ1 | Reinstate request_uri middleware (Superseded) | (REVISED) Retire custom PAR resolution; rely on native unless `ParPipelineMode=CustomFull` | (a) If Native/Adapter modes => no DB lookup; (b) Middleware no longer touches `request_uri` |
| PJ2 | Parameter merge precedence | Ensure JAR claims override query; detect mismatches | (a) Mismatch => RFC error; (b) Unit tests for precedence |
| PJ45 | Remove middleware JAR expansion | Shift JAR expansion to extract/validate event handler using service | (a) Middleware no longer processes `request`; (b) No duplicate logging / expansion |
| PJ46 | Response_mode normalization consolidation | Remove duplication; only event handler rewrites `response_mode=jwt` | (a) Middleware path removed; (b) Tests validate single normalization point |

### Epic E2 – JAR Validation Service
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ4 | Create `IJarValidationService` | Encapsulate decode + validate + map parameters | (a) Result object used exclusively by handlers; (b) Middleware no direct token handling |
| PJ5 | Alg / size enforcement | Enforce `AllowedRequestObjectAlgs`, max bytes | (a) Oversize rejected; (b) Unsupported alg rejected |
| PJ6 | Lifetime & skew rules | Unified exp/iat/nbf policy | (a) Exp window & iat skew tests pass |
| PJ7 | Iss/Aud/Client binding | issuer == client_id; aud == server | (a) Mismatch => invalid_request_object |
| PJ40 | Query vs request param conflict detection | Detect conflicting values (e.g. scope/state/redirect_uri) | (a) Conflict => invalid_request_object with mapped error reason |
| PJ41 | Claim & length limits | Enforce max claim count + per-value max length | (a) Violations produce structured errors |
| PJ37 | Built-in handler preemption | Suppress or short-circuit OpenIddict internal request object handlers | (a) No double validation; (b) Verified via trace ordering test |
| PJ38 | Extract stage integration | Perform validation + merge at `ExtractAuthorizationRequestContext` | (a) Query updated; (b) Sentinel parameter set `_jar_validated=1` |
| PJ17 | jti replay cache (moved) | Use service-level replay check | (a) Second use rejected; TTL honored |

### Epic E3 – PAR Store & Lifecycle
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ39 | PAR storage strategy decision | Evaluate: Native (reuse), Adapter (wrap), CustomFull | (a) ADR doc with decision; (b) Flag `ParStoreMode` set |
| PJ8 | Hash + dedupe semantics | If CustomFull or Adapter extension needed | (a) Duplicate returns same request_uri inside TTL |
| PJ9 | Consumption policy | Single vs multi-use | (a) Multi-use config works; second use blocked when single-use |
| PJ10 | Expiry scavenger | Background cleanup if CustomFull | (a) Metrics for deletions |
| PJ44 | Native reuse integration | If Native selected: mark request as PAR-resolved for enforcement | (a) Reliable detection in mode tests |

### Epic E4 – JARM Packaging
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ11 | JARM response builder | `IJarmResponseService` producing signed JWT | (a) Code/state claims; kid present |
| PJ12 | Error wrapping | Authorization errors in JARM | (a) Spec-compliant claim naming |
| PJ13 | Key selection | Active signing key rotation safe | (a) Key rotation test passes |
| PJ28 | (Moved) JARM success & error tests | Validate signatures, claims | (a) Code & error flows verified |

### Epic E5 – Mode Enforcement
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ14 | Enforce ParMode=Required | Reject non-PAR requests (accurate detection with native reuse) | (a) Missing PAR => invalid_request |
| PJ15 | Enforce JarMode=Required | Reject missing signed request object | (a) Works for direct & PAR flows |
| PJ16 | Enforce JarmMode=Required | Force response_mode=jwt | (a) Response JWT issued |
| PJ42 | Discovery gating by mode | Only advertise request_uri/request when enabled | (a) Metadata reflects active modes |

### Epic E6 – Security Hardening
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ18 | Audit logging | Accept/reject decisions (JAR/JARM/PAR) | (a) Structured entries with correlation id |
| PJ19 | Structured error codes | Error catalog mapping internal->spec | (a) Markdown published |
| PJ20 | Anti-bloat protections (refined) | Delegated to PJ41 + size limits | (a) See PJ41 acceptance |
| PJ43 | Remove obsolete PAR entity (if unused) | Drop table & migration if Native path selected | (a) Migration applied; docs updated |

### Epic E7 – Migration & Cleanup
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ21 | Remove unused placeholder code | Delete old expansion middleware portions | (a) No dead classes |
| PJ22 | Schema migration review | Index adequacy (only if CustomFull) | (a) ADR + migration |
| PJ23 | Config consolidation | Centralize feature flags | (a) `OidcAdvancedOptions` unified |
| PJ43 | (Cross-listed) Remove obsolete PAR entity | See above | (a) Completed post decision |

### Epic E8 – Testing
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ24 | Direct JAR happy path | RS256 + HS256 tests | (a) Fixtures green |
| PJ25 | PAR+JAR combined path | End-to-end expansion | (a) Parameter precedence validated |
| PJ26 | Required mode failures | Negative cases per mode | (a) Expected error codes |
| PJ27 | Replay tests | jti & request_uri replay | (a) Both blocked |
| PJ29 | Fuzz / malformed inputs | Random truncation / noise | (a) No unhandled exceptions |
| PJ46 | Validator performance baseline | Throughput & latency metrics | (a) Report committed |

### Epic E9 – Telemetry & Observability
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ30 | Metrics counters | par_requests_total, jar_validations_total, replays_blocked_total | (a) Scrape shows counters |
| PJ31 | Structured logging | TraceId correlation | (a) Sample log verified |
| PJ32 | Feature toggle health | Expose PAR/JAR/JARM mode status | (a) /healthz advanced section |

### Epic E10 – Documentation & DX
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ33 | Developer guide | Flow + sequence diagrams | (a) Markdown committed |
| PJ34 | Ops runbook | Key rotation & troubleshooting | (a) Linked from README |
| PJ35 | Config matrix | Mode combinations behavior | (a) Included in dev guide |
| PJ36 | Migration guide | Native -> Custom pipeline | (a) Dry-run script executed |

### Epic E11 – OpenIddict Integration Control
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ37 | Disable built-in request object validation (selectively) | Remove/override default handlers when `JarHandlerMode=CustomExclusive` | (a) Built-in handlers not invoked (trace) |
| PJ38 | Early extract merge | (Duplicate listing for visibility) | (a) See E2 acceptance |
| PJ44 | PAR native detection hook | Marker for native PAR resolution | (a) Flag available to enforcement logic |

## 4. Phased Delivery Plan (Updated)
| Phase | Scope | Exit Criteria |
|-------|-------|--------------|
| Phase 1 | E2 core (PJ4–PJ7, PJ5 size/alg, PJ6 lifetime), E11 (PJ37 partial), E1 (PJ45 removal), E5 basic enforcement (PJ15, PJ16), E8 initial tests (PJ24, PJ25), PJ19 error catalog draft | JAR validated centrally; no middleware expansion; required modes enforced; direct + PAR+JAR happy paths green |
| Phase 2 | E2 completion (PJ40, PJ41, PJ17 replay), E3 decision (PJ39) + chosen path integration (PJ44 or PJ8/9/10), E6 audit (PJ18), E8 negative+replay (PJ26, PJ27, PJ29), E9 metrics (PJ30) | Replay & conflict protection operational; metrics visible |
| Phase 3 | E4 JARM (PJ11–PJ13), E5 PAR required final (PJ14), E11 discovery gating (PJ42), E6 cleanup (PJ43), E9 health (PJ31, PJ32), Docs (PJ33–PJ35) | JARM production-ready; adaptive discovery; docs published |
| Phase 4 | E7 final cleanup (PJ21–PJ23), Migration guide (PJ36), Performance baseline (PJ46) | Migration documented; performance targets recorded |

## 5. Risk Register (Updated)
| Risk | Impact | Mitigation |
|------|--------|------------|
| Dual JAR validators (built-in + custom) | Inconsistent errors / security bypass | Early extract handler + disable built-in handlers (JarHandlerMode) |
| PAR detection ambiguity (native reuse) | False negatives for ParMode=Required | Introduce resolution marker parameter / transaction flag |
| Replay cache scalability | Missed replays under load | Pluggable IJarReplayCache (memory + distributed); perf tests (PJ46) |
| Claim bloat DOS | Performance degradation | Enforce claim count + size (PJ41) |
| Config drift vs discovery metadata | Client misconfiguration | Dynamic gating (PJ42) + automated tests |
| Removal of legacy entity w/out migration | Data loss | Migration script + ADR + explicit feature flag |

## 6. Config & Flags (Expanded)
| Name | Values | Phase | Notes |
|------|--------|-------|-------|
| ParPipelineMode | Native | Adapter | CustomFull | 2 | Selects PAR storage strategy |
| ParStoreMode (alias) | Native | Custom | 2 | Consolidate if needed (see ADR) |
| JarHandlerMode | BuiltIn | CustomExclusive | 1 | CustomExclusive suppresses OpenIddict built-ins |
| EnforceParRequired | bool | 3 | Deprecated after PJ14 full mode engine |
| EnforceJarRequired | bool | 1 | Transitions to mode-based enforcement |
| EnableJarm | bool | 3 | Gates JARM response JWT issuance |
| JarMaxBytes | int | 1 | Size control (maps to PJ5) |
| JarRequireJti | bool | 2 | Replay strengthening |
| JarClaimCountLimit | int | 2 | Anti-bloat (0 = unlimited) |
| JarClaimValueMaxLength | int | 2 | Anti-bloat per string claim (0 = unlimited) |
| JarEnforceQueryConsistency | bool | 2 | Toggle conflict rejection (PJ40) |
| JarClockSkewSeconds | int | 1 | Lifetime validation skew |
| JarMaxExpSeconds | int | 1 | Maximum exp horizon |
| ParReuseWindowSeconds | int | 2 | Hash dedupe window (custom store) |

## 7. Non-Goals (Explicit)
- Encrypted request objects (JWE) (future backlog separate)
- DPoP / MTLS binding integration (future)
- FAPI advanced profiles (not in current scope)
- Request object encryption or detached signatures

## 8. Acceptance Gate (Phase 3)
Must demonstrate:
- 95%+ branch coverage across validator + event handlers + JARM builder.
- All replay & negative path tests green.
- Zero unhandled exceptions in fuzz suite.
- Metrics visible & audited in logs.
- No built-in OpenIddict request object handler invoked under `JarHandlerMode=CustomExclusive` (trace assertion).

## 9. Immediate Next Actions (Sprint 1 Seed – Revised)
1. PJ4 – Introduce validator interface + RS256 path (central service).
2. PJ5 – Enforce alg + size + config flags.
3. PJ37 – Implement `JarHandlerMode=CustomExclusive` (suppress built-ins: unregister or short-circuit).
4. PJ45 – Remove middleware JAR expansion logic (leave minimal mode gate if needed).
5. PJ24 – Direct JAR RS256 + HS256 happy path tests updated to use service.
6. PJ19 – Draft error catalog (include new conflict/limit error reasons).
7. PJ6 – Lifetime & skew to prevent overly long exp.

## 10. Tracking & Mapping
Create GitHub issues per PJ id; label `area:oidc-advanced`. Milestones:
- `adv-par-phase1`, `adv-par-phase2`, `adv-par-phase3`, `adv-par-phase4`.
Add automation to enforce issue template referencing PJ id.

## 11. OpenIddict Source Assessment Summary
- Built-in PAR: Adequate for baseline persistence; lacks hash dedupe + multi-use policy -> implement only if needed (Adapter/CustomFull).
- Built-in request object validation: Not granular enough for per-client alg + claim limits + conflict detection; custom extraction + suppression required.
- Event pipeline: Early Extract + Validate hooks allow safe preemption without patching library.
- Discovery: Should not unconditionally advertise `request_uri` or custom `jwt` response_mode unless feature flags allow; update in PJ42.
- Existing middleware duplicates responsibilities now better handled by event handlers -> targeted for removal.

---
Updated backlog prepared for implementation alignment with OpenIddict integration findings.
