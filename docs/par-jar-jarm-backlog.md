# PAR / JAR / JARM Custom Stack Backlog

Status: Draft (Phase 1 wrap + Phase 2 planning)
Owner: Identity Platform
Last Updated: UTC {{DATE}}
Target Version: Phased (v1.1 – v1.4)

## Phase 1 Closure Summary
Scope Delivered:
- JAR core: validator (alg/size/lifetime/iss+aud), early extract merge, built-in preemption (partial), HS/RS happy paths.
- Mode enforcement (baseline): PAR required (middleware), JAR required, preliminary JARM injection.
- Error catalog draft + snapshot test (PJ54) to detect drift.
- Test coverage: positive JAR flows, negative size/alg/issuer/audience, PAR required denial, JAR required denial, secret length policy, initial replay (inconclusive), preemption sentinel.
- Configuration scaffolds for claim limits & conflict detection (not enforced yet).

Known Phase 1 Limitations:
- PAR push rejects JAR (`request_not_supported`) – adapter/extension not wired yet.
- Replay enforcement and metrics not completed (design only).
- Claim/length & conflict detection disabled (flags present).
- Discovery always advertises request/request_uri (no adaptive gating yet).
- JARM enforcement partially injected; end-to-end signed success/error JWT not fully asserted in tests.

## Phase 2 Focus (Adapter & Hardening)
Objectives:
1. Enable PAR + JAR interoperability (accept `request` at `/connect/par`).
2. Implement Native+Augmentation Adapter metadata (hash dedupe, consumption, metrics).
3. Enforce request/URL conflict detection & claim limits (config-driven, safe rollout).
4. Replay robustness (jti replay metrics & negative tests, configurable Jti TTL).
5. Mode enforcement reliability (PAR Required via resolution marker; remove middleware dependency).
6. Telemetry: counters (par_requests_total, par_reuse_hits_total, jar_validations_total, replays_blocked_total), structured logs.
7. Adaptive discovery gating for request/request_uri & jwt response_mode.
8. Clean negative/error matrix expansion + fuzz baseline.

## Phase 2 Backlog (Planned)
| ID | Title | Type | Goal | Notes |
|----|-------|------|------|-------|
| PJ47 | ParRequestMeta entity | Schema | Adjunct meta storage | Hash, reuse group, consumed flags |
| PJ48 | PAR push capture handler | Handler | Hash & dedupe reuse | Uses canonical param serialization |
| PJ49 | Authorize consumption handler | Handler | Single vs multi-use enforcement | Reads ParSingleUseDefault |
| PJ50 | PAR resolution marker | Handler | Reliable detection for enforcement | Inject `_par_resolved=1` + transaction flag |
| PJ51 | PAR metrics | Telemetry | Request/reuse counters | Tag reused vs new |
| PJ8  | Hash + dedupe semantics | Merge | (Alias of PJ48) | Status inherits PJ48 |
| PJ9  | Consumption policy | Merge | (Alias of PJ49) | Status inherits PJ49 |
| PJ10 | Expiry scavenger (optional) | Background | Cleanup expired meta | Configurable interval |
| PJ17 | JAR jti replay metrics | Security | Detect & count replays | Integrate cache + counters |
| PJ40 | Query vs request conflict detection | Validation | Reject mismatches | Controlled via EnforceQueryConsistency |
| PJ41 | Claim & length limits | Validation | Prevent bloat | ClaimCountLimit / ClaimValueMaxLength |
| PJ30 | Metrics counters foundation | Telemetry | par/jar/replay counters | Exported via existing metrics infra |
| PJ42 | Discovery gating | Integration | Advertise only enabled features | ParPipelineMode + JarHandlerMode + JARM flag |
| PJ14 | Enforce ParMode=Required (native) | Enforcement | Event-based rejection (no middleware) | Uses marker from PJ50 |
| PJ37 | Built-in handler suppression final | Hardening | Trace guarantee single validation | Add explicit disable list |
| PJ26 | Required mode negative matrix | Testing | Systematic failure coverage | PAR/JAR/JARM combinations |
| PJ27 | Replay tests (end-to-end) | Testing | Confirm jti+request_uri replays rejected | Distinguish PAR vs JAR replay |
| PJ29 | Fuzz / malformed inputs | Testing | Robustness & no crashes | Random truncation / mutated JWT parts |
| PJ11 | JARM success packaging final | JARM | Signed JWT success path assertions | Includes code & state claims |
| PJ12 | JARM error packaging final | JARM | Signed error JWT assertions | Standard claims + kid |
| PJ13 | JARM key rotation test | JARM | Ensure kid & signature validity across rotation | Uses active key snapshot |
| PJ18 | Audit logging enrichment | Observability | Structured accept/reject reasons | Include correlationId, clientId, alg |
| PJ31 | Health status extension | Observability | Advanced /healthz feature state | Modes + pipeline flags |
| PJ32 | Feature toggle health section | Observability | Show enabled adapter flags | JSON block |
| PJ33 | Developer guide updates | Docs | Adapter + flow diagrams | Link to full backlog |
| PJ34 | Ops runbook | Docs | Key rotation & troubleshooting | Replay/resuse guidance |
| PJ35 | Config matrix | Docs | Mode combination behavior | Table-based |
| PJ43 | Remove obsolete PAR entity | Cleanup | Drop unused table if adapter chosen | Post-rollout |

## Status Matrix (Summary)
| Story Group | Delivered | Phase 2 Planned | Phase 3+ |
|-------------|----------|-----------------|-----------|
| JAR Core | PJ4-7,37(partial),38 | PJ40, PJ41, PJ17, PJ37 final | Advanced profiles (future) |
| PAR Core | Baseline native only | PJ47–PJ51, PJ14 | CustomFull (if needed) |
| JARM | Skeleton handlers | PJ11–PJ13 finalize | Ext claims / encryption (future) |
| Enforcement | Basic middleware | Event-based (PJ14, PJ37 final) | Policy engine unification |
| Telemetry | Snapshot test (PJ54) | PJ30, PJ51, PJ17 metrics | SLA dashboards |
| Security | Basic validations | Replay, conflict, limits | Advanced DoS protections |
| Docs | Draft error catalog | PJ33–35 updates | Migration guide (Phase 4) |

## Milestone Targets
| Milestone | Scope | Exit Criteria |
|-----------|-------|--------------|
| v1.2 (Phase 2) | PAR Adapter + hardening | PAR reuse + single-use working; conflict/claim limits behind flags; metrics visible; negative matrix added |
| v1.3 (Phase 3) | JARM & discovery gating | JARM signed responses stable; adaptive metadata; PAR required reliable |
| v1.4 (Phase 4) | Cleanup & performance | Obsolete schema removed; perf baseline; migration guide |

## Appendix Link
Full original epic/story detail with acceptance criteria moved to: `docs/par-jar-jarm-backlog-full.md` (added if not present).

---
(Previous Phase 1 snapshot retained above; see appendix for deeper historical details.)
