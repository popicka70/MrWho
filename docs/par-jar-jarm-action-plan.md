# PAR/JAR/JARM Action Plan (Step-by-step)

Status: Active (Reprioritized for functional stability)
Owner: Identity Platform
Last Updated: UTC 2025-09-18
Scope: Replace built-in JAR handler safely, mature JARM, harden PAR, add metrics and docs.

## Guiding Principles
- Keep original behavior first, then iterate behind flags.
- Prefer additive handlers over invasive changes. Short-circuit built-ins until custom pipeline is stable.
- Ship in small, testable steps with visible metrics.
- Prioritize functional stability (no invalid_request/invalid_request_object/invalid_token) before expanding features/metrics.

---

## Reprioritized Goals (short-term)
1) Basic PAR and JAR happy paths must succeed for all relevant clients.
2) Remove sources of systemic rejection (global PKCE, missing HS256 secret) early.
3) Keep conflicts/limits disabled during stabilization.
4) Keep JARM opt-in only until validated end-to-end.

---

## Workstream A — Handler Isolation & Replacement (PJ37, PJ40, PJ41)
- A0: Per-app PKCE (functional unblock)
  - Remove global `RequireProofKeyForCodeExchange()` from server options.
  - Enforce PKCE per-client by adding `Requirements.Features.ProofKeyForCodeExchange` in `BuildDescriptor` when `RequirePkce=true`.
  - Temporarily set `RequirePkce=false` for clients that don’t yet send PKCE in tests.
- A1: Verify short-circuit works end-to-end
  - Tests: built-in handler is not invoked when `_jar_validated=1` is present.
  - Assert no double processing of `request` param across extract/validate stages.
- A2: Introduce parity handler
  - Add `MrWhoJarRequestJwtValidationHandler` mirroring OpenIddict behavior.
  - Register with a feature flag `OidcAdvanced:Jar:UseCustomCore=true|false`.
- A3: Migrate to custom handler by default
  - Flip feature flag default to `true` after parity test suite passes.
  - Keep short-circuit only for safety window; plan removal in A4.
- A4: Remove short-circuit and legacy shims
  - Delete short-circuit handlers once our handler is authoritative and stable.

Definition of Done (A):
- Parity tests green; regression suite covers success, alg/size/exp/iat/iss/aud, replay, param merge, conflicts.
- Toggle documented; defaults set; rollout notes prepared.

---

## Workstream B — Conflicts & Limits (PJ40, PJ41)
- B1: Configuration surface
  - Expose `OidcAdvanced:RequestConflicts:*` and `OidcAdvanced:RequestLimits:*` with sane defaults.
- B2: Limits coverage
  - Tests for name/value length, aggregate bytes, scope items, acr_values.
- B3: Conflict coverage
  - Tests for scope, redirect_uri, response_type, state, nonce.
- B4: Fuzz & Unicode
  - Negative cases for oversize and malformed inputs; ensure stable rejections.

Definition of Done (B):
- Config-driven behavior; matrix tests pass; metrics record granular failure reasons.

Notes:
- Keep RequestConflicts and RequestLimits disabled by default during stabilization.

---

## Workstream C — JARM Packaging (PJ11, PJ12, PJ13)
- C0: Keep JARM opt-in
  - Only package when `response_mode=jwt` or client requires it; do not default to JARM yet.
- C1: Success JWT assertions
  - iss/aud/iat/exp/state/code present; RS256 sign; kid set.
- C2: Error JWT assertions
  - error + error_description mapping; state preserved.
- C3: Rotation readiness
  - Tests validating new kid during rotation; previous kid acceptance window as applicable.
- C4: Discovery alignment
  - Advertise response_mode `jwt` and JARM signing algs; gate if disabled (see PJ42).

Definition of Done (C):
- Green E2E tests for success/error; rotation test stable; discovery accurate.

---

## Workstream D — PAR Hardening & Instrumentation (PJ48–PJ51, PJ56)
- D1: Push/reuse metrics
  - Counters for push accepted/reused/rejected.
- D2: Consumption metrics
  - Resolved/consumed/expired/missing/error.
- D3: Single-use enforcement tests
  - Matrix for required/optional; race/replay attempts.

Definition of Done (D):
- Metrics visible via ProtocolMetrics endpoint; tests cover outcomes.

---

## Workstream E — Replay & Security Metrics (PJ17, PJ27)
- E1: JAR replay metrics
  - Increment `jar.replay` on jti cache hits at extract/validate stages.
- E2: End-to-end replay tests
  - Same JAR reused across PAR and direct authorize; late-stage retries.

Definition of Done (E):
- Replay counters exposed; E2E tests enforce rejections.

---

## Workstream F — Observability & Ops (PJ18, PJ31, PJ32)
- F1: Audit enrichment
  - Structured fields for reasons: `limit:*`, `conflict:*`, `replay`, `par:*`, `jarm:*`.
- F2: Health endpoints
  - `/healthz` reports feature/flag states and basic counters.
- F3: Protocol metrics UX
  - Expand debug/metrics endpoints to include JAR/JARM outcomes.

Definition of Done (F):
- Operators can see feature states and rejection reasons; minimal runbook prepared.

---

## Workstream G — Docs & Migration (PJ33, PJ34, PJ35)
- G1: Developer guide
  - Handler ordering, sentinels, flags, config keys, testing notes.
- G2: Ops runbook
  - Replay/DoS guidance; limits tuning; discovery gating.
- G3: Config matrix
  - PAR/JAR/JARM mode combinations and expected behaviors.

Definition of Done (G):
- Docs committed; linked from README; CI check for stale dates.

---

## Immediate Next (1–2 sprints)
- A0: Per-app PKCE (remove global, add per-client requirement).
- A2: JAR HS256 secret fallback path in `AuthorizationHandler.ValidateAndApplyJarAsync` (use DB client secret if history not present and not "{HASHED}"; length >= 32). Add metric `jar.secret.fallback`.
- Keep conflicts/limits disabled; verify defaults and tests don’t flip them.
- Ensure `redirect_uri` fallback handlers run before core validators (extract + validate order check).
- C0: Keep JARM opt-in; add simple success/error E2E validations.

## Readiness Criteria for “no invalid tokens”
- Non-PAR/JAR authorize flow issues code and token successfully.
- PAR push + authorize with `request_uri` issues code and token (single-use default enforced; second use rejected with proper error).
- JAR HS256/RS256 authorize flows succeed; replays rejected; oversize/exp/iat invalid return clear errors.
- Issuer configured correctly (OpenIddict:Issuer matches base URL).
- Confidential clients using HS256 JAR have secrets >= 32 bytes.

## References
- Code: `MrWho/Services/JarJarmServerEventHandlers.cs`, `MrWho/Handlers/AuthorizationHandler.cs`
- Flags/Options: `MrWho/Options/OidcAdvancedOptions.cs`, `appsettings*.json`
- Discovery: custom handler in `JarJarmServerEventHandlers` (Configuration)
- Metrics: `MrWho/Services/ProtocolMetrics.cs`, `ProtocolMetricsController`
