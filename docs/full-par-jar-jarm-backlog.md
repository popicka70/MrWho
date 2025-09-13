# Full PAR + JAR + JARM Implementation Backlog

_Status: in progress_

## Legend
- [ ] Not started
- [~] In progress / partially done
- [x] Completed

## Tier 1 – Core Refactor
| ID | Item | Notes | Status |
|----|------|-------|--------|
| 1 | Extract reusable JAR validator service | `IJarRequestValidator` created & registered | [x] |
| 2 | Refactor `JarRequestExpansionMiddleware` to use validator | Middleware now uses validator & simplified | [x] |
| 3 | Accept `request` (JAR) in PAR POST | Custom `/connect/par` controller added (validates & stores) | [x] |
| 4 | Resolve `request_uri` at `/connect/authorize` | Implemented in middleware (`_par_resolved` marker) | [x] |

## Tier 2 – Policy Enforcement
| ID | Item | Notes | Status |
|----|------|-------|--------|
| 5 | Enforce `ParMode` (Required) | Pending | [ ] |
| 6 | Enforce `JarMode` (Required) | Pending | [ ] |
| 7 | Enforce `JarmMode` (Required) | Pending | [ ] |
| 8 | Conditional discovery augmentation | Pending refinement | [ ] |

## Tier 3 – Client Adjustments
| ID | Item | Notes | Status |
|----|------|-------|--------|
| 9 | Re?enable PAR on demo client | Next | [ ] |
|10 | Ensure JAR built before challenge (PAR push) | After 9 | [ ] |
|11 | Fallback retry logic (optional) | Pending | [ ] |

## Tier 4 – Testing
| ID | Item | Notes | Status |
|----|------|-------|--------|
|12 | Add test: PAR + JAR + JARM happy path | Pending | [ ] |
|13 | Negative: `ParMode=Required` without PAR | Pending | [ ] |
|14 | Negative: `JarMode=Required` missing JAR | Pending | [ ] |
|15 | Negative: `JarmMode=Required` w/out response_mode | Pending | [ ] |
|16 | Replay test (same JAR via PAR twice) | Pending | [ ] |
|17 | Alg policy test (HS512 + short secret) | Pending | [ ] |

## Tier 5 – Hardening & Ops
| ID | Item | Notes | Status |
|----|------|-------|--------|
|18 | Hash & store `ParametersHash` for PAR | Pending | [ ] |
|19 | Optimize PAR cleanup background service | Pending | [ ] |
|20 | OpenTelemetry spans for JAR/JARM/PAR | Pending | [ ] |
|21 | Security audit enrichment | Pending | [ ] |

## Tier 6 – Docs & UX
| ID | Item | Notes | Status |
|----|------|-------|--------|
|22 | Update client configuration docs | Pending | [ ] |
|23 | Admin UI: surface effective enforcement | Pending | [ ] |
|24 | Admin diagnostics: recent PAR entries | Pending | [ ] |
|25 | README / high-level architecture section | Pending | [ ] |

## Technical Details / Design Notes
- **Single Source Validation**: `IJarRequestValidator` ensures identical logic across front-channel and PAR POST.
- **PAR+JAR**: When JAR present in PAR POST, only `client_id` + `request_uri` appear in authorization URL; JAR stays back-channel.
- **Mode Enforcement Order**: PAR (ensures transport), then JAR (integrity), then JARM (response packaging).
- **Fallback Rules**: Only permissible when corresponding `*Mode != Required`.
- **Security**: Replay prevention via `jti` + replay cache; secret length policy enforced before HS* signature validation.

## Open Questions (To Clarify Before Implementation)
1. Should PAR store raw JAR JWT or expanded param map (or both)? (Current plan: store raw + normalized JSON for flexibility.)
2. Should `request_uri` resolution re-validate signature or trust cached success? (Favor trust + optional hash compare.)
3. JARM encryption (future) needed or signing only is sufficient short-term? (Current scope: signing only.)

## Next Immediate Actions
- Implement Tier 2 policy enforcement (ParMode/JarMode/JarmMode) and re-enable demo client PAR.

---
Generated automatically. Update status markers as tasks progress.
