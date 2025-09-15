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
  - PJ25 (Initial PAR+JAR+JARM happy paths HS256 + RS256 via new test classes)
  - PJ45 (Middleware JAR expansion removed; stub left for mode enforcement only)
  - PJ19 (Error catalog draft committed)
  - PJ40/PJ41 scaffolds (JarOptions placeholders) ✅ Scaffolded (no enforcement)
  - PJ37 (Preemption trace test & functional suppression)
  - Tests: oversize, alg=none, issuer mismatch, audience mismatch, HS/RS PAR+JAR+JARM, PAR/JAR mode failures, RSA key invalid, secret policy, preemption replay sentinel
- In Progress (🛠):
  - Error catalog snapshot stability test (new PJ54) – ensures mapping drift detection
- Upcoming (🎯 before Sprint 1 close): finalize PJ54 snapshot, summarize coverage gaps, Sprint 1 acceptance sign-off.

## Newly Added Story (Sprint 1 Hardening)
| ID | Story | Description | Acceptance Criteria |
|----|-------|-------------|---------------------|
| PJ54 | Error catalog snapshot test | Guard against unintended internal reason drift | (a) Test fails if reasons added/removed without review |

## 9. Immediate Next Actions (Sprint 1 – Remaining)
1. PJ54 – Commit snapshot test for error catalog reasons.
2. Document remaining Phase 2 items (PAR adapter, replay metrics) in backlog summary.
3. Sprint 1 wrap: update acceptance checklist & mark phase readiness.

---
(Sections below unchanged.)
