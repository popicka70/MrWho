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
| 4a | Per-client RSA public key property | `JarRsaPublicKeyPem` added to `Client` entity | [x] |
| 4b | Validator uses client RSA key | Fallback to server keys if none provided | [x] |
| 4c | Migration for `JarRsaPublicKeyPem` | Added EF migration & snapshot updated | [x] |

## Tier 2 – Policy Enforcement
| ID | Item | Notes | Status |
|----|------|-------|--------|
| 5 | Enforce `ParMode` (Required) | Implemented in middleware (par.resolved check) | [x] |
| 6 | Enforce `JarMode` (Required) | Implemented in middleware (jar_expanded/from_par) | [x] |
| 7 | Enforce `JarmMode` (Required) | Middleware forces `mrwho_jarm` when required | [x] |
| 8 | Conditional discovery augmentation | Pending refinement | [ ] |

## Tier 3 – Client Adjustments
| ID | Item | Notes | Status |
|----|------|-------|--------|
| 9 | Re?enable PAR on demo client | PAR client + AutoParPush re-enabled | [x] |
|10 | Ensure JAR built before challenge (PAR push) | JAR always built (JarOnlyWhenLarge=false, AutoJar=true) | [x] |
|11 | Fallback retry logic (optional) | Pending | [ ] |
|12 | Admin UI input for RSA JAR public key | Field added to client edit (Flows & Grants) | [x] |

## Tier 4 – Testing
| ID | Item | Notes | Status |
|----|------|-------|--------|
|13 | Test: PAR + JAR + JARM happy path (HS) | Pending | [ ] |
|14 | Test: PAR + JAR + JARM happy path (RS) | Requires client RSA key setup | [ ] |
|15 | Negative: `ParMode=Required` without PAR | Pending | [ ] |
|16 | Negative: `JarMode=Required` missing JAR | Pending | [ ] |
|17 | Negative: `JarmMode=Required` w/out response_mode | Pending | [ ] |
|18 | Replay test (same JAR via PAR twice) | Pending | [ ] |
|19 | Alg policy test (HS512 + short secret) | Pending | [ ] |
|20 | Invalid RSA public key rejected | Pending | [ ] |

## Tier 5 – Hardening & Ops
| ID | Item | Notes | Status |
|21 | Hash & store `ParametersHash` for PAR | Pending | [ ] |
|22 | Optimize PAR cleanup background service | Pending | [ ] |
|23 | OpenTelemetry spans for JAR/JARM/PAR | Pending | [ ] |
|24 | Security audit enrichment | Pending | [ ] |

## Tier 6 – Docs & UX
| ID | Item | Notes | Status |
|----|------|-------|--------|
|25 | Update client configuration docs (RSA JAR) | Pending | [ ] |
|26 | Admin UI: surface effective enforcement | Pending | [ ] |
|27 | Admin diagnostics: recent PAR entries | Pending | [ ] |
|28 | README / high-level architecture section | Pending | [ ] |

## Technical Details / Design Notes
- **Per-client RSA JAR**: Client stores PEM public key; validator uses it when alg starts with RS; server keys remain fallback for legacy clients.
- **Security**: Still enforces jti replay prevention + exp window; symmetric secret length policy unchanged.

## Next Immediate Actions
- Implement RS256 happy path test (Task 14) using a generated RSA key + setting JarRsaPublicKeyPem.

---
Generated automatically. Update status markers as tasks progress.
