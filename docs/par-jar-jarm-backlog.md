# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (Phase 2 wrap rebaseline)
Owner: Identity Platform
Last Updated: UTC 2025-09-16 (Re-assessed + metrics instrumentation pass)
Target Version: Phased (v1.1 – v1.4)

## Phase 2 Progress Snapshot (Rebaseline)
Completed (✅):
- PJ48 PAR push capture endpoint implemented (hash+reuse, accepts `request`)
- PJ49 PAR authorize consumption (single-use enforcement via option)
- PJ50 PAR resolution marker (sentinel `_par_resolved` + consumption handler) ✅ (moved from In Progress)
- PJ51 PAR metrics counters (push/reuse/resolution/consumed/replay/conflict/limit hooks) – core counters defined
- PJ14 Native ParMode=Required enforcement (event handler) – middleware fallback now obsolete
- PJ37 Built-in handler suppression final (legacy middleware removed; native JarMode & ParMode enforcement active)
- JAR validator core (alg/size/lifetime/issuer/audience/jti replay + early extract merge) – Success & negative path coverage
- Dynamic discovery augmentation (request/request_uri supported, response_mode jwt, dynamic HS alg advertisement)

In Progress (🛠):
- PJ40 Query vs request conflict detection (implemented in early extract + validation handlers behind config; needs config surface + full matrix tests)
- PJ41 Claim & length limits (limit handler implemented; needs configuration exposure, tuning & fuzz coverage)
- PJ11 JARM success packaging final (handler issues signed JWT, needs end-to-end post-auth tests & claim assertions)
- PJ12 JARM error packaging final (error path JWT emitted; need negative/error scenario tests)
- PJ30 Metrics counters foundation (ProtocolMetrics service extended; PAR/JAR/JARM/validation observers partially wired)
- PJ56 JAR/JARM & extended PAR metrics wiring (jar/jarm + par resolution observers added; remaining: push reuse, consumed granular outcomes)

Pending (🎯 next):
- PJ17 JAR jti replay metrics (extend existing replay cache usage -> add counters + export) – counter placeholder present (`replay` outcome, need full tests)
- PJ42 Discovery gating refinements (adaptive advertise based on active clients/modes; current state = always-on advertise)
- PJ13 JARM key rotation test (kid stability & validation across rotation) – needs test harness
- PJ26 Required mode negative matrix (systematic ParMode/JarMode/JarmMode failure assertions)
- PJ27 Replay tests (end-to-end) – extend to PAR + JAR multi-stage replay and late-stage duplicate detection
- PJ29 Fuzz / malformed inputs (oversize claims, unicode, structured tampering) against new limit handler
- PJ18 Audit logging enrichment (add structured reasons for JAR/JARM packaging, limit & conflict rejections)
- PJ31 Health status extension (/healthz feature state exposure)
- PJ32 Feature toggle health section (show RequestLimits/RequestConflicts gating status)
- PJ33 Developer guide updates (adapter diagrams + handler ordering)
- PJ34 Ops runbook (replay/reuse guidance; configuring limits safely)
- PJ35 Config matrix (behavior combinations including modes + limits + conflicts)
- PJ43 Remove obsolete PAR entity (Cleanup) – Deferred

## Phase 1 Closure Summary (Unchanged Reference)
Scope Delivered:
- JAR core: validator (alg/size/lifetime/iss+aud), early extract merge, built-in preemption (now fully exclusive path), HS/RS happy paths.
- Mode enforcement: PAR required (native), JAR required (native), JARM injection & packaging.
- Error catalog draft + snapshot test (PJ54) to detect drift.
- Test coverage: positive JAR flows, negative size/alg/issuer/audience, PAR required denial, JAR required denial, secret length policy, replay (basic), preemption sentinel, conflict & limit rejection tests (PJ40/PJ41 scenarios).
- Configuration scaffolds for claim limits & conflict detection.

Known Phase 1 Limitations (addressed / remaining):
- PAR push rejects JAR (`request_not_supported`) – RESOLVED (PJ48).
- Replay metrics pending (PJ17).
- Claim/length & conflict detection still behind config gates (rollout phased) – PARTIAL (handlers exist; gating + docs pending).
- Discovery still static (adaptive gating pending PJ42) – PARTIAL.
- JARM signed success/error JWT assertions pending (PJ11–PJ13) – IN PROGRESS.

## Phase 2 Focus (Adapter & Hardening)
Objectives (updated status):
1. PAR + JAR interoperability ✅
2. Adapter metadata + metrics ✅ core (needs JAR/JARM counters wiring -> PJ56)
3. Conflict & claim limits 🛠 (handlers implemented; enable + test)
4. Replay robustness ⏳ (add metrics + extended scenarios)
5. Mode enforcement reliability ✅ (middleware removed, native handlers active)
6. Telemetry expansion 🛠 (ProtocolMetrics present; need emission wiring + exposure endpoints)
7. Adaptive discovery gating ⏳ (currently unconditional advertise; add feature-driven gating)
8. Negative/error matrix + fuzz ⏳ (expand tests for conflicts/limits/JARM)

## Phase 2 Backlog (Updated)
| ID | Title | Type | Goal | Status |
|----|-------|------|------|--------|
| PJ47 | ParRequestMeta entity | Schema | Adjunct meta storage | (Merged) |
| PJ48 | PAR push capture handler | Handler | Hash & dedupe reuse | ✅ Done |
| PJ49 | Authorize consumption handler | Handler | Single vs multi-use enforcement | ✅ Done |
| PJ50 | PAR resolution marker | Handler | Reliable detection | ✅ Done |
| PJ51 | PAR metrics | Telemetry | Request/reuse/resolution/consumed/replay/conflict/limit hooks | ✅ Core counters defined |
| PJ14 | Enforce ParMode=Required (native) | Enforcement | Event-based rejection | ✅ Done |
| PJ40 | Query vs request conflict detection | Validation | Reject mismatches | 🛠 In Progress |
| PJ41 | Claim & length limits | Validation | Prevent bloat | 🛠 In Progress |
| PJ17 | JAR jti replay metrics | Security | Detect & count replays | Pending |
| PJ30 | Metrics counters foundation | Telemetry | jar/jarm/replay counters infra | 🛠 Partial (extended snapshot) |
| PJ56 | JAR/JARM metrics wiring | Telemetry | Increment & expose jar/jarm counters | 🛠 Partial (JAR/JARM + basic PAR resolution) |
| PJ42 | Discovery gating | Integration | Adaptive advertise | Pending |
| PJ37 | Built-in handler suppression final | Hardening | Single validation trace | ✅ Done |
| PJ26 | Required mode negative matrix | Testing | Systematic failures | Pending |
| PJ27 | Replay tests (end-to-end) | Testing | Reject replays | Pending |
| PJ29 | Fuzz / malformed inputs | Testing | Robustness | Pending |
| PJ11 | JARM success packaging final | JARM | Signed response assertions | 🛠 In Progress |
| PJ12 | JARM error packaging final | JARM | Signed error assertions | 🛠 In Progress |
| PJ13 | JARM key rotation test | JARM | kid validity across rotation | Pending |
| PJ18 | Audit logging enrichment | Observability | Structured reasons | Pending |
| PJ31 | Health status extension | Observability | /healthz feature state | Pending |
| PJ32 | Feature toggle health section | Observability | Show adapter flags | Pending |
| PJ33 | Developer guide updates | Docs | Adapter diagrams | Pending |
| PJ34 | Ops runbook | Docs | Replay/reuse guidance | Pending |
| PJ35 | Config matrix | Docs | Behavior combinations | Pending |
| PJ43 | Remove obsolete PAR entity | Cleanup | Drop unused table | Deferred |

## Status Matrix (Summary)
| Story Group | Delivered | Phase 2 In Progress | Phase 3+ |
|-------------|----------|---------------------|-----------|
| JAR Core | PJ4-7,37,38 | PJ40, PJ41, PJ17 | Advanced profiles |
| PAR Core | PJ48, PJ49, PJ51, PJ14, PJ50 | Replay tests | CustomFull |
| JARM | Packaging handlers (success+error) | PJ11–PJ13 (tests, rotation) | Encryption/advanced |
| Enforcement | Native PAR/JAR/JARM | Conflict & limits finalization | Unified policy engine |
| Telemetry | PAR counters + snapshot | JAR/JARM wiring (PJ56), replay metrics (PJ17) | SLA dashboards |
| Security | Validations baseline | Replay metrics, conflict, limits | DoS protections |
| Docs | Error catalog | Adapter/ops docs | Migration guide |

## Milestone Targets (Reaffirmed)
| Milestone | Scope | Exit Criteria |
|-----------|-------|--------------|
| v1.2 (Phase 2) | PAR Adapter + hardening | PAR reuse + single-use, conflict/claim limits (gated) active, core metrics visible (PAR + basic JAR), JARM packaging handler present |
| v1.3 (Phase 3) | JARM & discovery gating | JARM assertions tests, adaptive metadata, replay + JAR metrics complete |
| v1.4 (Phase 4) | Cleanup & performance | Schema cleanup + perf baseline + migration guide |

## Immediate Next Actions (Week Focus)
1. Finalize PAR push/reuse/consumed instrumentation (extend push controller & consumption handler) (PJ51/PJ56)
2. Add detailed conflict/limit outcome codes (e.g. conflict:client_id, limit:scope_items) to validation metrics
3. Implement JARM success/error claim assertion tests (iss,aud,iat,exp,state,code/error mapping) (PJ11/PJ12)
4. Add key rotation + historical JARM validation test (PJ13)
5. Build required-mode negative matrix generator (covers ParMode/JarMode/JarmMode permutations) (PJ26)
6. Replay scenario expansion: same JAR reused across PAR push + direct authorize, and late-stage replay after partial consumption (PJ27)
7. Draft adaptive discovery gating logic (counts active clients requiring features) (PJ42)

## Risk / Watchlist
- Conflict & limit handlers currently fail-open on internal exceptions (log at Debug). Evaluate tightening once stable.
- Discovery advertising HS algs may over-expose if clients removed; gating logic pending (PJ42).
- JARM packaging currently always RS256; consider advertising and enforcing separate JARM signing alg policy.

## Appendix Link
Full original epic/story detail with acceptance criteria moved to: `docs/par-jar-jarm-backlog-full.md`.

---
(Previous Phase 1 snapshot retained above; see appendix for historical details.)
