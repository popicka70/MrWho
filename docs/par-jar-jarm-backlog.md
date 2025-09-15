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
  - PJ7 (Issuer/Audience binding enforced; tests added)
  - PJ24 (Direct JAR happy path HS256 + RS256)
  - PJ45 (Middleware JAR expansion removed; stub left for mode enforcement only)
  - PJ37 (Partial) – CustomExclusive early extract handler preempts built-in by stripping `request` param after validation
  - Tests updated: oversize, alg=none, issuer mismatch, audience mismatch
- In Progress (🛠):
  - PJ25 (PAR+JAR combined path verification) 
  - PJ19 (Error catalog markdown drafting)
  - PJ37 (Trace proof of built-in handler suppression)
- Upcoming (🎯 remainder Sprint 1): PJ25, PJ19, PJ37 trace test, scaffolds for PJ40/PJ41.

(Original backlog follows; statuses will be updated incrementally.)

## 0. Context Snapshot (Current State)
- PAR: Relying on OpenIddict native pushed authorization endpoint (built-in persistence). Custom `PushedAuthorizationRequest` entity present but NOT wired into live flow.
- PAR Strategy DECIDED: Adopt Native+Augmentation ("Adapter") approach.
- JAR: Central validator & early extract handler active (PJ4/5/6/7/37 partial). Legacy middleware expansion removed.
- JARM: Event handlers active; no new changes this sprint.
- Mode flags: Basic JarMode=Required enforcement via middleware stub.
- Replay: jti logic present; full replay test in Phase 2.
- Discovery: Static; gating pending.
- Risk: Built-in JAR handlers neutralized.

## 3. Detailed Backlog (Status Updates)
### Epic E2 – JAR Validation Service (excerpt)
| ID | Story | Status | Notes |
|----|-------|--------|-------|
| PJ4 | Validation service | ✅ | Implemented |
| PJ5 | Alg/size | ✅ | Enforced per client + max bytes |
| PJ6 | Lifetime/skew | ✅ Impl | Tests to expand later |
| PJ7 | Iss/Aud binding | ✅ | Enforcement & tests added |
| PJ37 | Preemption | Partial | Need trace assertion test |
| PJ38 | Early merge | ✅ | `_jar_validated=1` sentinel |

### Epic E8 – Testing (excerpt)
| ID | Story | Status | Notes |
|----|-------|--------|------|
| PJ24 | Direct JAR happy path | ✅ | HS256 + RS256 tests |
| PJ25 | PAR+JAR combined | 🛠 | Implementing PAR push test |

## 9. Immediate Next Actions (Sprint 1 – Remaining)
1. PJ25 – Implement PAR+JAR combined path test (native PAR + request_uri + JAR validation).
2. PJ19 – Commit initial error catalog markdown (map reasons -> OIDC codes).
3. PJ37 – Add log-based or diagnostic tracing test ensuring built-in handler not invoked (absence of duplicate validation log).
4. Prep scaffolds for PJ40/PJ41 (config option placeholders) without enforcement.
5. Update backlog statuses & finalize Sprint 1 acceptance checklist.

---
(Backlog truncated above for brevity; unchanged sections remain below)
