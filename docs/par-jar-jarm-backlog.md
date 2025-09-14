# PAR / JAR / JARM Custom Stack Backlog

Status: Draft
Owner: Identity Platform
Last Updated: UTC {{DATE}}
Target Version: Phased (v1.1 – v1.3)

## 0. Context Snapshot (Current State)
- PAR: Native OpenIddict permission advertised (optional). No custom request_uri resolution in middleware.
- JAR: Partial validation inside `AuthorizationHandler` (direct request only). No central service, limited replay protection.
- JARM: Not implemented (modes inert).
- Mode flags (ParMode/JarMode/JarmMode): Largely informational; strict enforcement missing.
- Custom PAR DB entity exists but unused by pipeline.
- Replay cache & JAR expansion middleware removed.

## 1. Objectives
1. Provide a self-contained custom pipeline for PAR/JAR/JARM (opt-in).
2. Enforce per?client modes (Disabled / Optional / Required) consistently.
3. Centralize JAR validation (alg whitelist, size, exp/iat/nbf, iss/aud, jti replay, signature) with clear error semantics.
4. Implement JARM (signed JWT auth responses) when requested & permitted.
5. Maintain fallbacks: ability to toggle between native PAR and custom PAR.
6. Deliver comprehensive automated test coverage.

## 2. High-Level Epics
| Epic | Title | Goal | Priority |
|------|-------|------|----------|
| E1 | Middleware & Routing Layer | Restore custom resolver & expansion | High |
| E2 | JAR Validation Service | Single authoritative validator | High |
| E3 | PAR Store & Lifecycle | Secure, replay-safe storage | High |
| E4 | JARM Packaging | JWT-wrapped auth responses | Medium |
| E5 | Mode Enforcement | Consistent Required/Optional behavior | High |
| E6 | Security Hardening | Replay, integrity, logging | High |
| E7 | Migration & Cleanup | Remove dead code / config drift | Medium |
| E8 | Test Suite Expansion | Confidence + regression safety | High |
| E9 | Telemetry & Observability | Operational insight | Medium |
| E10 | Documentation & DX | Clear guidance & toggles | Medium |

## 3. Detailed Backlog
### Epic E1 – Middleware & Routing
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ1 | Reinstate request_uri middleware | Reintroduce `JarRequestExpansionMiddleware` to resolve stored PAR entries before OpenIddict | (a) Removes `request_uri`; (b) Attaches expanded parameters; (c) Marks consumed flag |
| PJ2 | Parameter merge precedence | Ensure JAR claims override query unless conflict + mismatch check | (a) Mismatch yields RFC-compliant error; (b) Unit test covers precedence |
| PJ3 | Config toggle native vs custom PAR | App setting `ParPipelineMode` (Native|Custom) | (a) Switching to Custom suppresses advertising pushed_authorization permission; (b) Smoke tests pass both modes |

### Epic E2 – JAR Validation Service
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ4 | Create `IJarValidationService` | Encapsulate decode + validate + map parameters | (a) Returns structured result object; (b) No direct token handler calls in middleware/auth handler |
| PJ5 | Alg / size enforcement | Enforce `AllowedRequestObjectAlgs`, max bytes | (a) Oversize rejected; (b) Unsupported alg rejected |
| PJ6 | Lifetime & skew rules | Unified exp/iat/nbf policy | (a) Exp > max window rejected; (b) iat outside skew rejected |
| PJ7 | Iss/Aud/Client binding | Ensure issuer=client_id & aud matches server | (a) Mismatch yields invalid_request_object; tests added |

### Epic E3 – PAR Store & Lifecycle
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ8 | Hash + dedupe semantics | Store hash of canonical parameter set | (a) Duplicate submission returns same request_uri if within TTL (configurable) |
| PJ9 | Consumption policy | Single-use or multi-use (config flag) | (a) If single-use, second resolve => invalid_request_uri |
| PJ10 | Expiry scavenger | Background cleanup | (a) Timer job deletes expired rows; metric emitted |

### Epic E4 – JARM Packaging
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ11 | JARM response builder | `IJarmResponseService` producing signed JWT | (a) Code/state inside claims; (b) kid header present |
| PJ12 | Error wrapping | Authorization errors wrapped when response_mode=jwt | (a) Conforms to spec claim naming; tests verify parsing |
| PJ13 | Key selection | Use active signing key (rotate-compatible) | (a) Changing primary key rotates JARM correctly |

### Epic E5 – Mode Enforcement
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ14 | Enforce ParMode=Required | Reject non-PAR authorize requests | (a) Returns invalid_request; tests pass |
| PJ15 | Enforce JarMode=Required | Reject when no signed request object supplied | (a) Works for both direct & PAR flows |
| PJ16 | Enforce JarmMode=Required | Force/normalize response_mode=jwt | (a) Auth flow returns JWT response |

### Epic E6 – Security Hardening
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ17 | jti replay cache | Distributed in-memory abstraction | (a) Second use rejected; TTL respected |
| PJ18 | Audit logging | Log accept/reject decisions | (a) Audit entries with outcome & correlation id |
| PJ19 | Structured error codes | Map internal failure reasons to OIDC errors + doc | (a) Error catalog markdown published |
| PJ20 | Anti-bloat protections | Enforce claim count & string length limits | (a) Oversize claim set rejected with specific error |

### Epic E7 – Migration & Cleanup
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ21 | Remove unused placeholder code | Delete obsolete expansion placeholders | (a) No dead classes lingering |
| PJ22 | Schema migration review | Confirm PAR table indexes adequate | (a) Index coverage documented; migration generated |
| PJ23 | Config consolidation | Document & centralize feature flags | (a) Single `OidcAdvancedOptions` class |

### Epic E8 – Testing
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ24 | Direct JAR happy path | RS256 + HS256 tests | (a) Separate fixtures; green |
| PJ25 | PAR+JAR combined path | End-to-end test with expansion | (a) Confirms parameter precedence |
| PJ26 | Required mode failures | Par/Jar/Jarm required negative cases | (a) All produce expected error codes |
| PJ27 | Replay tests | jti & request_uri replay rejection | (a) Both blocked; timing test |
| PJ28 | JARM success & error | Validate signatures, claims presence | (a) Code & error flows verified |
| PJ29 | Fuzz / malformed inputs | Random truncation & claims noise | (a) No unhandled exceptions |

### Epic E9 – Telemetry & Observability
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ30 | Metrics (Prometheus style) | Counters: par_requests_total, jar_validations_total, replays_blocked_total | (a) Scrape endpoint shows counters |
| PJ31 | Structured logging | TraceId correlation for each auth journey | (a) Log sample includes correlation id |
| PJ32 | Feature toggle health | Expose current PAR/JAR/JARM mode status | (a) /healthz advanced section |

### Epic E10 – Documentation & DX
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ33 | Developer guide | Flow diagrams + sequence charts | (a) Markdown committed under /docs/identity |
| PJ34 | Ops runbook | Key rotation, cache purge, diagnosing failures | (a) Linked from README |
| PJ35 | Config matrix | Table of mode combinations & behavior | (a) Included in developer guide |
| PJ36 | Migration guide | Steps to switch native -> custom stack | (a) Tested dry-run script |

## 4. Phased Delivery Plan
| Phase | Scope | Exit Criteria |
|-------|-------|--------------|
| Phase 1 | E1 (core middleware), E2 partial (RS/HS validation), E5 (Par/Jar required), E6(PJ17), E8 basic tests | All happy paths + required enforcement stable |
| Phase 2 | E2 complete, E3, E6 (audit), E8 replay & negative tests, E9 metrics | Replay & audit operational |
| Phase 3 | E4 (JARM), E5 JarmMode, E6 remaining, E9 full, E10 docs | JARM usable in production toggle |
| Phase 4 | E7 cleanup, E10 migration guide | Native ? custom toggle documented |

## 5. Risk Register
| Risk | Impact | Mitigation |
|------|--------|------------|
| Dual PAR paths conflict | Incorrect enforcement | Single toggle + integration test matrix |
| Replay cache scalability | Missed replays under load | Pluggable distributed store (IMemory + IDistributed) |
| Key rotation race for JARM | Invalid response verification | Embed kid + publish JWKS pre-rotation |
| Spec drift | Non-compliant responses | Add spec conformance tests (OIDC test suite subset) |

## 6. Config & Flags (Target)
| Name | Values | Phase | Notes |
|------|--------|-------|-------|
| ParPipelineMode | Native |Custom| 1 | Controls middleware activation |
| EnforceParRequired | bool | 1 | Shortcut until full mode engine |
| EnforceJarRequired | bool | 1 | Ditto |
| EnableJarm | bool | 3 | Gated until JARM stable |
| JarMaxBytes | int | 1 | Size control |
| JarRequireJti | bool | 2 | Replay strengthening |
| ParReuseWindowSeconds | int | 2 | Hash dedupe window |

## 7. Non-Goals (Explicit)
- Encrypted request objects (JWE) (future backlog separate)
- DPoP / MTLS binding integration (future)
- FAPI advanced profiles (not in current scope)

## 8. Acceptance Gate (Phase 3)
Must demonstrate:
- 95%+ branch coverage across middleware + validator + JARM builder.
- All replay & negative path tests green.
- Zero unhandled exceptions in fuzz suite.
- Metrics visible & audited in logs.

## 9. Immediate Next Actions (Sprint 1 Seed)
1. PJ1 – Restore middleware skeleton behind feature flag (Custom mode off by default).
2. PJ4 – Introduce validator interface + RS256 path.
3. PJ14/PJ15 – Simple mode enforcement switches.
4. PJ24 – Direct JAR RS256 happy path test.
5. PJ19 – Draft error catalog (map internal -> spec codes).

## 10. Tracking & Mapping
Create Azure DevOps / GitHub issues per PJ id; label `area:oidc-advanced`. Use milestones: `adv-par-phase1`, `adv-par-phase2`, etc.

---
Prepared for future implementation. Update this file as epics complete.
