# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (Phase 1 wrap + Phase 2 planning / in progress)
Owner: Identity Platform
Last Updated: UTC 2025-09-15
Target Version: Phased (v1.1 – v1.4)

## Phase 2 Progress Snapshot
Completed (✅):
- PJ48 PAR push capture endpoint implemented (hash+reuse, accepts `request`)
- PJ49 PAR authorize consumption (single-use enforcement via option)
- PJ51 PAR metrics counters (push/reuse/resolution/consumed/replay)
- PJ14 Native ParMode=Required enforcement (event handler) – middleware fallback now obsolete

In Progress (🛠):
- PJ50 Resolution marker (sentinel `_par_resolved` in place via resolution handler; finalize transaction flag wiring later)
- PJ37 Built-in handler suppression final (partial; still allowing middleware stub)

Pending (🎯 next):
- PJ40 Query vs request conflict detection
- PJ41 Claim & length limits
- PJ17 JAR jti replay metrics (extend existing replay cache usage)
- PJ42 Discovery gating refinements (adaptive advert)

## Phase 1 Closure Summary
Scope Delivered:
- JAR core: validator (alg/size/lifetime/iss+aud), early extract merge, built-in preemption (partial), HS/RS happy paths.
- Mode enforcement (baseline): PAR required (middleware), JAR required, preliminary JARM injection.
- Error catalog draft + snapshot test (PJ54) to detect drift.
- Test coverage: positive JAR flows, negative size/alg/issuer/audience, PAR required denial, JAR required denial, secret length policy, initial replay (inconclusive), preemption sentinel.
- Configuration scaffolds for claim limits & conflict detection (not enforced yet).

Known Phase 1 Limitations:
- PAR push rejects JAR (`request_not_supported`) – adapter/extension not wired yet. (RESOLVED in Phase 2 via PJ48).
- Replay enforcement and metrics not completed (design only).
- Claim/length & conflict detection disabled (flags present).
- Discovery always advertises request/request_uri (no adaptive gating yet).
- JARM enforcement partially injected; end-to-end signed success/error JWT not fully asserted in tests.

## Phase 2 Focus (Adapter & Hardening)
Objectives:
1. Enable PAR + JAR interoperability (accept `request` at `/connect/par`). ✅
2. Implement Native+Augmentation Adapter metadata (hash dedupe, consumption, metrics). ✅ core (hash/reuse, single-use) / metrics.
3. Enforce request/URL conflict detection & claim limits (config-driven, safe rollout). ⏳
4. Replay robustness (jti replay metrics & negative tests, configurable Jti TTL). ⏳
5. Mode enforcement reliability (PAR Required via resolution marker; remove middleware dependency). ✅ (PJ14)
6. Telemetry: counters (par_requests_total, par_reuse_hits_total, jar_validations_total, replays_blocked_total), structured logs. ✅ PAR counters; jar/replay pending.
7. Adaptive discovery gating for request/request_uri & jwt response_mode. ⏳
8. Clean negative/error matrix expansion + fuzz baseline. ⏳

## Phase 2 Backlog (Planned / Updated)
| ID | Title | Type | Goal | Status |
|----|-------|------|------|--------|
| PJ47 | ParRequestMeta entity | Schema | Adjunct meta storage | (Merged in existing entity usage) |
| PJ48 | PAR push capture handler | Handler | Hash & dedupe reuse | ✅ Done |
| PJ49 | Authorize consumption handler | Handler | Single vs multi-use enforcement | ✅ Done |
| PJ50 | PAR resolution marker | Handler | Reliable detection | Partial (sentinel present) |
| PJ51 | PAR metrics | Telemetry | Request/reuse counters | ✅ Done |
| PJ14 | Enforce ParMode=Required (native) | Enforcement | Event-based rejection | ✅ Done |
| PJ40 | Query vs request conflict detection | Validation | Reject mismatches | Pending |
| PJ41 | Claim & length limits | Validation | Prevent bloat | Pending |
| PJ17 | JAR jti replay metrics | Security | Detect & count replays | Pending |
| PJ30 | Metrics counters foundation | Telemetry | jar/replay counters | Partial (PAR done) |
| PJ42 | Discovery gating | Integration | Adaptive advertise | Pending |
| PJ37 | Built-in handler suppression final | Hardening | Single validation trace | Partial |
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
| PJ43 | Remove obsolete PAR entity | Cleanup | Drop unused table | Deferred (post-v1.2) |

## Status Matrix (Summary)
| Story Group | Delivered | Phase 2 In Progress | Phase 3+ |
|-------------|----------|---------------------|-----------|
| JAR Core | PJ4-7,37(partial),38 | PJ40, PJ41, PJ17, PJ37 final | Advanced profiles |
| PAR Core | PJ48, PJ49, PJ51, PJ14 | PJ50 finalize, replay tests | CustomFull (if needed) |
| JARM | Skeleton handlers | PJ11–PJ13 | Encryption/advanced |
| Enforcement | Native PAR + JARM inject | Conflict & limits | Unified policy engine |
| Telemetry | PAR counters, snapshot test | JAR/replay counters | SLA dashboards |
| Security | Basic validations | Replay, conflict, limits | DoS protections |
| Docs | Error catalog draft | Adapter/ops docs | Migration guide |

## Milestone Targets
| Milestone | Scope | Exit Criteria |
|-----------|-------|--------------|
| v1.2 (Phase 2) | PAR Adapter + hardening | PAR reuse + single-use working; conflict/claim limits flags; metrics visible; negative matrix added |
| v1.3 (Phase 3) | JARM & discovery gating | JARM signed responses stable; adaptive metadata; replay metrics |
| v1.4 (Phase 4) | Cleanup & performance | Obsolete schema removed; perf baseline; migration guide |

## Appendix Link
Full original epic/story detail with acceptance criteria moved to: `docs/par-jar-jarm-backlog-full.md`.

---
(Previous Phase 1 snapshot retained above; see appendix for deeper historical details.)
