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
|13 | Test: PAR + JAR + JARM happy path (HS) | Implemented (JarParJarmAdditionalTests#Par_Jar_Hs256_Jarm_Happy_Path_Works) | [x] |
|14 | Test: PAR + JAR + JARM happy path (RS) | Implemented (JarRsParJarmHappyPathTests) | [x] |
|15 | Negative: `ParMode=Required` without PAR | Implemented (JarParJarmAdditionalTests#ParMode_Required_Without_Par_Fails) | [x] |
|16 | Negative: `JarMode=Required` missing JAR | Implemented (JarParJarmAdditionalTests#JarMode_Required_Missing_Jar_Fails) | [x] |
|17 | Negative: `JarmMode=Required` w/out response_mode | Implemented (JarmModeEnforcementTests#JarmMode_Required_Without_ResponseMode_Query_Is_Enforced) | [x] |
|18 | Replay test (same JAR via PAR twice) | Implemented (JarParJarmAdditionalTests#Par_Jar_Replay_Jti_Fails_On_Second_Push) | [x] |
|19 | Alg policy test (HS512 + short secret) | Implemented (JarParJarmAdditionalTests#CreateClient_HS512_ShortSecret_Rejected) | [x] |
|20 | Invalid RSA public key rejected | Implemented (JarParJarmAdditionalTests#Par_With_Invalid_Rsa_Public_Key_Fails) | [x] |

## Tier 5 – Hardening & Ops
| ID | Item | Notes | Status |
|----|------|-------|--------|
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
- Implement PAR request ParametersHash storage (Task 21) + background cleanup (Task 22).

---
Generated automatically. Update status markers as tasks progress.
