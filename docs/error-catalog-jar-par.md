# OIDC Advanced Error Catalog (Draft)

Status: Draft
Last Updated: UTC {{DATE}}
Scope: JAR / PAR / JARM custom pipeline errors – internal reason -> external OIDC mapping.

## 1. Mapping Table
| Internal Reason | External `error` | error_description (example) | Notes |
|-----------------|------------------|-----------------------------|-------|
| empty request object | invalid_request_object | empty request object | JAR basic validation |
| request object too large | invalid_request_object | request object too large | Size > MaxRequestObjectBytes |
| request object must be JWT | invalid_request_object | request object must be JWT | Not 3-part JWT |
| missing alg | invalid_request_object | missing alg | Header missing alg |
| client_id mismatch | invalid_request_object | client_id mismatch | Query vs JAR mismatch |
| client_id missing | invalid_request_object | client_id missing | Absent in both query & payload |
| unknown client | invalid_client | unknown client | Client disabled/absent |
| alg not allowed | invalid_request_object | alg not allowed | Not in per-client whitelist |
| alg not supported | invalid_request_object | alg not supported | Outside default RS256/HS256 set |
| exp invalid | invalid_request_object | exp invalid | Expired or > max window |
| iat invalid | invalid_request_object | iat invalid | Future beyond skew or too old |
| nbf in future | invalid_request_object | nbf in future | nbf > now + skew |
| jti required | invalid_request_object | jti required | RequireJti enabled and jti absent |
| jti replay | invalid_request_object | jti replay | Replay cache hit |
| client secret missing | invalid_request_object | client secret missing | HS* alg no secret |
| client secret length below policy | invalid_request_object | client secret length below policy | HS key too short |
| signature invalid | invalid_request_object | signature invalid | Token handler failed |
| invalid client JAR public key | invalid_request_object | invalid client JAR public key | Bad RSA key |
| iss invalid | invalid_request_object | iss invalid | issuer != client_id |
| aud invalid | invalid_request_object | aud invalid | audience mismatch |
| conflict parameter mismatch | invalid_request_object | parameter conflict (query vs request object) | (Planned PJ40) |
| claim count limit | invalid_request_object | too many claims in request object | (Planned PJ41) |
| claim value too long | invalid_request_object | claim value too long | (Planned PJ41) |
| invalid request object | invalid_request_object | invalid request object | Generic fallback |
| request object required for this client | invalid_request | request object required for this client | JarMode=Required missing |
| invalid_request_uri_reuse_policy | invalid_request_uri | request uri already consumed | (Planned PAR single-use) |

## 2. Error Code Usage Guidelines
- Prefer targeted internal reasons for telemetry; external codes remain spec-compliant.
- Never emit sensitive values in `error_description` (no raw JWT, secrets, or hashes).
- Map unrecognized failures to `invalid_request_object` unless clearly authentication related (`invalid_client`).

## 3. Telemetry Dimensions
Recommended metric label dimensions:
- jar_validation_outcome: success | failure
- jar_failure_reason: (internal reason key)
- client_id
- alg

## 4. Planned Enhancements (Phase 2/3)
| Feature | Internal Reasons Affected | Notes |
|---------|---------------------------|-------|
| Query consistency enforcement (PJ40) | conflict parameter mismatch | Compare redirect_uri, scope, code_challenge, etc. |
| Claim/length limits (PJ41) | claim count limit, claim value too long | Configurable via JarOptions |
| PAR reuse policy | invalid_request_uri_reuse_policy | Single-use vs multi-use toggle |
| Replay metrics | jti replay | Dedicated counter replays_blocked_total |

## 5. Implementation Checklist
- [x] Document current reasons
- [ ] Emit structured log with `reason` field everywhere JAR validation fails
- [ ] Introduce constants enum/class for internal reasons
- [ ] Unit tests asserting mapping stability (snapshot)

## 6. Future Considerations
- Localization of `error_description` (external only)
- Separate internal diagnostic code vs public description tokens
- Correlation id propagation in all error responses

---
Draft – refine as PJ40/PJ41/PAR adapter implemented.
