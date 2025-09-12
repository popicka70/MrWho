# Symmetric Secret Policy (HS* Algorithms)

Status: Active (Phase 1 Security Core)
Scope: Applies to client secrets used for:
- HMAC-based request object signing (JAR)
- Any future HS* usages (e.g. token introspection HMAC) when enabled

## 1. Minimum Length Requirements
| Algorithm | Minimum Bytes | Recommended Bytes | Notes |
|-----------|---------------|-------------------|-------|
| HS256     | 32            | 48                | 256-bit security baseline |
| HS384     | 48            | 64                | Avoid unless required for interop |
| HS512     | 64            | 64                | Preferred for new high-assurance clients |

Enforcement occurs during:
- Client create/update (API rejects below-policy secrets)
- JAR request object validation (middleware gates usage)
- Discovery metadata generation (HS* algs only advertised if at least one compliant client implies/declares them)

## 2. Discovery Behavior
The `request_object_signing_alg_values_supported` list is computed dynamically:
- Always includes `RS256`
- Includes `HS256` if any JAR-enabled client either:
  - Explicitly lists it in `AllowedRequestObjectAlgs`, or
  - Leaves alg list empty (default fallback implies HS256 + RS256)
- Includes `HS384`/`HS512` only if at least one client explicitly allows them AND the stored secret length satisfies policy
- If no compliant HS* algorithms remain, they are omitted entirely (privacy-by-omission)

## 3. Error Messages & UX Principles
- Server responses use generic phrasing: `client secret length below policy` (no exact size leakage)
- Admin UI pre-validates and blocks save with specific guidance: "Selected algorithms require >= N bytes secret (current M)."
- Rotation guidance is surfaced in docs (below) rather than detailed production error messages.

## 4. Rotation & Upgrade Procedure
Scenario: Upgrade HS256 (32B) secret to support HS512 (64B)
1. Generate a new 64-byte secret (see Section 5). Do NOT reuse or pad the old value.
2. Update the client record with the new secret (API or Admin UI) — validation ensures min length.
3. (Optional) Expand `AllowedRequestObjectAlgs` to include `HS512` (or leave empty to rely on defaults if HS256/RS256 still desired).
4. Deploy change; new signed request objects can now use HS512.
5. Invalidate the old secret (remove from rotation lists / secret manager versions). Avoid dual-valid secrets longer than strictly necessary.

Downgrade Attempt (e.g., 64B -> 48B while retaining HS512):
- Prevented by policy; request fails until HS512 removed from effective configuration or secret restored to >= 64B.

## 5. Secure Secret Generation
Recommended approaches:
- .NET CLI (PowerShell): `[Convert]::ToBase64String((New-Object byte[] 64 | %{(Get-Random -Max 256)}) )` (then trim padding as needed)
- OpenSSL: `openssl rand -base64 64`
- Password manager high-entropy generator (?64 raw bytes, not characters) — verify byte length post-decoding if base64.

Guidelines:
- Store secrets in a secure secret store (Azure Key Vault, AWS Secrets Manager, etc.).
- NEVER commit secrets to source control.
- Prefer random binary -> Base64Url (strip padding '=') for compactness.

## 6. Client Configuration Rules
| Field | Behavior |
|-------|----------|
| AllowedRequestObjectAlgs (empty) | Implies RS256 + HS256 (if secret length ?32B) |
| Explicit HS384 inclusion | Requires secret ?48B |
| Explicit HS512 inclusion | Requires secret ?64B |
| Removing HS512 | Allows rotation to shorter secret (but not below any remaining HS* requirements) |

## 7. Operational Monitoring (Future Enhancements)
Planned (not yet implemented):
- Metric: `mrwho_policy_symmetric_secret_noncompliant_total`
- Periodic audit scan for sub-policy secrets introduced externally

## 8. Testing Strategy (Implemented)
Implemented unit tests cover:
- Boundary failures and passes: 31/32, 47/48, 63/64 bytes
- Downgrade attempt (64B -> 48B with HS512)
- Discovery omission when no HS384/HS512 clients exist

Gaps (intentional defer):
- Multi-realm distinct alg advertisement (future realm-aware service)
- Parallel secret rotation overlap race conditions

## 9. Migration / Legacy Handling
- Historical hashed secrets marked with redaction markers (e.g. `{HASHED}`) bypass length validation only during JAR runtime verification to maintain test/demo backward compatibility.
- New plaintext submissions MUST comply; hashed markers should be re-hashed from compliant raw values.

## 10. Quick FAQ
**Q: Why not always advertise all HS* algs?**
A: Minimizes attack surface & avoids misleading clients into using unsupported / weakly-backed algorithms.

**Q: Can we allow automatic padding of short secrets?**
A: Rejected to preserve cryptographic clarity and prevent silent downgrade risk.

**Q: Are character counts the same as byte counts?**
A: Not always. Policy uses UTF-8 byte length. ASCII-only secrets map 1:1; multibyte characters reduce effective entropy.

---
**Action:** Mark Item 5 DONE after merging this document.
