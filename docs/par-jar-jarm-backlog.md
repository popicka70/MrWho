# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (Phase 2 wrap rebaseline)
Owner: Identity Platform
Last Updated: UTC 2025-09-19 (Code-audit sync + metrics wiring review)
Target Version: Phased (v1.1 – v1.4)

## Phase 2 Progress Snapshot (Rebaseline)
Completed (✅):
- PJ48 PAR push capture endpoint implemented (hash+reuse, accepts `request`)
- PJ49 PAR authorize consumption (single-use enforcement via option)
- PJ50 PAR resolution marker (sentinel `_par_resolved` + consumption handler)
- PJ51 PAR metrics counters (push/reuse/resolution/consumed/replay/conflict/limit hooks) – core counters defined
- PJ14 Native ParMode=Required enforcement (event handler) – middleware fallback now obsolete
- PJ37 Built-in handler suppression final (legacy middleware removed; native JarMode & ParMode enforcement active)
- JAR validator core (alg/size/lifetime/issuer/audience/jti replay + early extract merge) – Success & negative path coverage
- Dynamic discovery augmentation (request/request_uri supported, response_mode jwt, dynamic HS alg advertisement)
- JARM response mode normalization (response_mode=jwt normalized to `mrwho_jarm` at extract/validate stages)

In Progress (🛠):
- PJ40 Query vs request conflict detection (handler enabled for scope via early extract + validation; needs broader matrix tests + docs)
- PJ41 Claim & length limits (limit handler implemented; needs configuration exposure, tuning & fuzz coverage)
- PJ11 JARM success packaging final (handler issues signed RS256 JWT with iss/aud/iat/exp/code/state; needs end-to-end post-auth tests & claim assertions)
- PJ12 JARM error packaging final (error path JWT emitted; negative/error scenario tests pending)
- PJ30 Metrics counters foundation (ProtocolMetrics extended; PAR/JAR/JARM/validation observers wired; export/UX pending)
- PJ56 JAR/JARM & extended PAR metrics wiring (JAR/JARM + PAR resolution wired; remaining: PAR push created/reused + consumed granular outcomes)
- PJ17 JAR jti replay metrics (counters wired via replay cache hits; test coverage and dashboards pending)
- PJ26 Required mode negative matrix (some tests present for PAR required and JAR required; expand to full matrix + realms/defaults)
- PJ27 Replay tests (end-to-end) – initial PAR+JAR replay covered; extend to cross-channel and late-stage duplicates

Pending (🎯 next):
- PJ42 Discovery gating refinements (adaptive advertise based on active clients/modes; current state = always-on advertise)
- PJ13 JARM key rotation test (kid stability & validation across rotation) – needs test harness
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
- Replay metrics pending (PJ17) – PARTIAL (counters wired; tests pending).
- Claim/length & conflict detection still behind config gates (rollout phased) – PARTIAL (handlers exist; gating + docs pending).
- Discovery still static (adaptive gating pending PJ42) – PARTIAL.
- JARM signed success/error JWT assertions pending (PJ11–PJ13) – IN PROGRESS.

## Phase 2 Focus (Adapter & Hardening)
Objectives (updated status):
1. PAR + JAR interoperability ✅
2. Adapter metadata + metrics ✅ core (needs PAR push/JAR/JARM counter completeness -> PJ56)
3. Conflict & claim limits 🛠 (handlers implemented; enable + test)
4. Replay robustness 🛠 (counters wired; extend scenarios + tests)
5. Mode enforcement reliability ✅ (middleware removed, native handlers active)
6. Telemetry expansion 🛠 (ProtocolMetrics present; wire remaining emissions + expose snapshot endpoints)
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
| PJ40 | Query vs request conflict detection | Validation | Reject mismatches | 🛠 Handler enabled; tests + docs |
| PJ41 | Claim & length limits | Validation | Prevent bloat | 🛠 In Progress |
| PJ17 | JAR jti replay metrics | Security | Detect & count replays | 🛠 Counters wired; tests pending |
| PJ30 | Metrics counters foundation | Telemetry | jar/jarm/replay counters infra | 🛠 Wired; export/UX pending |
| PJ56 | JAR/JARM metrics wiring | Telemetry | Increment & expose jar/jarm counters | 🛠 Partial (JAR/JARM + PAR resolution; push wiring pending) |
| PJ42 | Discovery gating | Integration | Adaptive advertise | Pending |
| PJ37 | Built-in handler suppression final | Hardening | Single validation trace | ✅ Done |
| PJ26 | Required mode negative matrix | Testing | Systematic failures | 🛠 Partial (PAR/JAR required tests) |
| PJ27 | Replay tests (end-to-end) | Testing | Reject replays | 🛠 Initial PAR replay; extend |
| PJ29 | Fuzz / malformed inputs | Testing | Robustness | Pending |
| PJ11 | JARM success packaging final | JARM | Signed response assertions | 🛠 Handler done; tests pending |
| PJ12 | JARM error packaging final | JARM | Signed error assertions | 🛠 Handler done; tests pending |
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
| PAR Core | PJ48, PJ49, PJ51, PJ14, PJ50 | Replay tests, push metrics wiring | CustomFull |
| JARM | Packaging handlers (success+error) + response_mode normalization | PJ11–PJ13 (tests, rotation) | Encryption/advanced |
| Enforcement | Native PAR/JAR/JARM | Conflict & limits finalization | Unified policy engine |
| Telemetry | ProtocolMetrics with JAR/JARM + PAR resolution | PAR push wiring (PJ56), replay dashboards (PJ17) | SLA dashboards |
| Security | Validations baseline | Replay metrics, conflict, limits | DoS protections |
| Docs | Error catalog | Adapter/ops docs | Migration guide |

## Milestone Targets (Reaffirmed)
| Milestone | Scope | Exit Criteria |
|-----------|-------|--------------|
| v1.2 (Phase 2) | PAR Adapter + hardening | PAR reuse + single-use, conflict/claim limits (gated) active, core metrics visible (PAR + JAR), JARM packaging handler present |
| v1.3 (Phase 3) | JARM & discovery gating | JARM assertions tests, adaptive metadata, replay + JAR metrics complete |
| v1.4 (Phase 4) | Cleanup & performance | Schema cleanup + perf baseline + migration guide |

## Immediate Next Actions (Week Focus)
1. Wire and validate PAR push metrics (created/reused) in push controller; ensure consumed outcomes are granular (PJ51/PJ56)
2. Expand validation metrics with detailed outcome codes and finalize docs (e.g., conflict:client_id, limit:scope_items) (PJ40/PJ41)
3. Implement JARM success/error claim assertion tests (iss,aud,iat,exp,state,code/error mapping) (PJ11/PJ12)
4. Add key rotation + historical JARM validation test (PJ13)
5. Extend required-mode negative matrix generator (ParMode/JarMode/JarmMode permutations across realm defaults vs client overrides) (PJ26)
6. Replay scenario expansion: same JAR reused across PAR push + direct authorize, and late-stage replay after partial consumption (PJ27)
7. Draft adaptive discovery gating logic (counts active clients requiring features) (PJ42)
8. Expose ProtocolMetrics snapshot via admin/diagnostics endpoint for quick verification (PJ30/PJ56)

## Risk / Watchlist
- Conflict & limit handlers currently fail-open on internal exceptions (log at Debug). Evaluate tightening once stable.
- Discovery advertising HS algs may over-expose if clients removed; gating logic pending (PJ42).
- JARM packaging currently always RS256; consider advertising and enforcing separate JARM signing alg policy.

## Appendix Link
Full original epic/story detail with acceptance criteria moved to: `docs/par-jar-jarm-backlog-full.md`.

---
(Previous Phase 1 snapshot retained above; see appendix for historical details.)
