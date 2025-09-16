# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (Phase 1 wrap + Phase 2 planning / in progress)
Owner: Identity Platform
Last Updated: UTC 2025-09-16
Target Version: Phased (v1.1 – v1.4)

## Phase 2 Progress Snapshot
Completed (✅):
- PJ48 PAR push capture endpoint implemented (hash+reuse, accepts `request`)
- PJ49 PAR authorize consumption (single-use enforcement via option)
- PJ51 PAR metrics counters (push/reuse/resolution/consumed/replay)
- PJ14 Native ParMode=Required enforcement (event handler) – middleware fallback now obsolete
- PJ37 Built-in handler suppression final (legacy middleware removed; native JarMode & ParMode enforcement active)

In Progress (🛠):
- PJ50 Resolution marker (sentinel `_par_resolved` in place; finalize transaction flag wiring later)

Pending (🎯 next):
- PJ40 Query vs request conflict detection
- PJ41 Claim & length limits
- PJ17 JAR jti replay metrics (extend existing replay cache usage)
- PJ42 Discovery gating refinements (adaptive advert)

## Phase 1 Closure Summary
Scope Delivered:
- JAR core: validator (alg/size/lifetime/iss+aud), early extract merge, built-in preemption (now fully exclusive path), HS/RS happy paths.
- Mode enforcement: PAR required (native), JAR required (native), JARM injection & packaging.
- Error catalog draft + snapshot test (PJ54) to detect drift.
- Test coverage: positive JAR flows, negative size/alg/issuer/audience, PAR required denial, JAR required denial, secret length policy, replay (basic), preemption sentinel, conflict & limit rejection tests (PJ40/PJ41 scenarios).
- Configuration scaffolds for claim limits & conflict detection.

Known Phase 1 Limitations (addressed / remaining):
- PAR push rejects JAR (`request_not_supported`) – RESOLVED (PJ48).
- Replay metrics pending (PJ17).
- Claim/length & conflict detection still behind config gates (rollout phased).
- Discovery still static (adaptive gating pending PJ42).
- JARM signed success/error JWT assertions pending (PJ11–PJ13).

## Phase 2 Focus (Adapter & Hardening)
Objectives:
1. PAR + JAR interoperability ✅
2. Adapter metadata + metrics ✅ core
3. Conflict & claim limits ⏳
4. Replay robustness ⏳
5. Mode enforcement reliability ✅ (middleware removed)
6. Telemetry expansion ⏳ (add jar_validations_total, jar_replay_blocked_total)
7. Adaptive discovery gating ⏳
8. Negative/error matrix + fuzz ⏳

## Phase 2 Backlog (Planned / Updated)
| ID | Title | Type | Goal | Status |
|----|-------|------|------|--------|
| PJ47 | ParRequestMeta entity | Schema | Adjunct meta storage | (Merged) |
| PJ48 | PAR push capture handler | Handler | Hash & dedupe reuse | ✅ Done |
| PJ49 | Authorize consumption handler | Handler | Single vs multi-use enforcement | ✅ Done |
| PJ50 | PAR resolution marker | Handler | Reliable detection | In Progress |
| PJ51 | PAR metrics | Telemetry | Request/reuse counters | ✅ Done |
| PJ14 | Enforce ParMode=Required (native) | Enforcement | Event-based rejection | ✅ Done |
| PJ40 | Query vs request conflict detection | Validation | Reject mismatches | Pending |
| PJ41 | Claim & length limits | Validation | Prevent bloat | Pending |
| PJ17 | JAR jti replay metrics | Security | Detect & count replays | Pending |
| PJ30 | Metrics counters foundation | Telemetry | jar/replay counters | Partial |
| PJ42 | Discovery gating | Integration | Adaptive advertise | Pending |
| PJ37 | Built-in handler suppression final | Hardening | Single validation trace | ✅ Done |
| PJ26 | Required mode negative matrix | Testing | Systematic failures | Pending |
| PJ27 | Replay tests (end-to-end) | Testing | Reject replays | Pending |
| PJ29 | Fuzz / malformed inputs | Testing | Robustness | Pending |
| PJ11 | JARM success packaging final | JARM | Signed response assertions | Pending |
| PJ12 | JARM error packaging final | JARM | Signed error assertions | Pending |
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
| PAR Core | PJ48, PJ49, PJ51, PJ14 | PJ50 finalize, replay tests | CustomFull |
| JARM | Skeleton handlers | PJ11–PJ13 | Encryption/advanced |
| Enforcement | Native PAR/JAR/JARM | Conflict & limits | Unified policy engine |
| Telemetry | PAR counters | JAR/replay counters | SLA dashboards |
| Security | Validations baseline | Replay, conflict, limits | DoS protections |
| Docs | Error catalog | Adapter/ops docs | Migration guide |

## Milestone Targets
| Milestone | Scope | Exit Criteria |
|-----------|-------|--------------|
| v1.2 (Phase 2) | PAR Adapter + hardening | PAR reuse + single-use, conflict/claim limits gated, core metrics visible |
| v1.3 (Phase 3) | JARM & discovery gating | JARM assertions + adaptive metadata + replay metrics |
| v1.4 (Phase 4) | Cleanup & performance | Schema cleanup + perf baseline + migration guide |

## Appendix Link
Full original epic/story detail with acceptance criteria moved to: `docs/par-jar-jarm-backlog-full.md`.

---
(Previous Phase 1 snapshot retained above; see appendix for historical details.)
