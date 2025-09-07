# Persistent Signing & Encryption Keys (JWKS + Rotation)

Last updated: 2025-09-07

## Purpose
Provide durable, database-backed signing and encryption keys for the OpenID Connect server, with automated rotation and overlapping JWKS publication so existing tokens continue to validate during rollovers.

## What Changed (High level)
- Keys are now stored in the application database (KeyMaterials table) instead of dev certs.
- OpenIddict loads credentials from DB on startup and publishes them via the discovery JWKS.
- Rotation automatically creates a new primary key and gracefully retires the old one after a configurable overlap.
- Safe fallbacks exist so the server can still start (ephemeral keys) if DB is not ready.

## Data Model
Entity: KeyMaterial
- Use: sig or enc
- Kid: stable key identifier (kid) used in JWKS and token headers
- Algorithm: JWA name (e.g., RS256 for signing, RSA-OAEP for encryption)
- KeyType: RSA (future: EC)
- KeySize: bits (2048 default)
- PrivateKeyPem: PKCS#8 private key (PEM)
- CreatedAt, ActivateAt, RetireAt, RevokedAt
- IsPrimary: current primary for the given Use
- Status: Created, Active, Retiring, Retired, Revoked

Indexes
- Unique: Kid
- Composite: (Use, IsPrimary), (Use, Status, ActivateAt)

Migration
- 20250907130810_KeyManagement creates the KeyMaterials table and indexes.

## Algorithms & Formats
- Signing: RS256 by default (configurable)
- Encryption: RSA-OAEP by default (configurable), with AES-256-CBC-HS512 content encryption
- Private key storage: PKCS#8 PEM
- kid generation: Base64Url(SHA-256(SPKI bytes)) of the public key

## Services & Components
- IKeyManagementService
  - EnsureInitializedAsync: creates bootstrap sig/enc keys if none exist
  - GetActiveKeysAsync: returns SecurityKeys for keys in Active or Retiring status
  - Rotation: promotes a new primary when the current primary is older than RotationInterval; marks old primary as Retiring until RetireAt, then Retired

- KeyRotationHostedService (BackgroundService)
  - Runs at startup and every few hours
  - Ensures initial keys exist and applies rotation policy

- OpenIddictServerCredentialsConfigurator (IPostConfigureOptions<OpenIddictServerOptions>)
  - Ensures keys, loads DB-backed keys, and sets SigningCredentials/EncryptionCredentials
  - If DB is not ready, uses ephemeral RSA keys so the server can start
  - Can disable access token encryption based on configuration

## JWKS Publication & Token Flow
- OpenIddict publishes the public keys (JWKS) from the credentials configured at startup.
- Both Active and Retiring keys are advertised in JWKS:
  - New tokens are signed using the current primary Active key
  - Recently issued tokens remain verifiable because the previous key stays in Retiring state for an overlap period
- After RetireAt, a Retiring key becomes Retired and is no longer advertised

## Configuration (appsettings)
Section: KeyManagement
- Enabled: true
- SigningKeySize: 2048
- EncryptionKeySize: 2048
- RotationInterval: ISO 8601 time span (e.g., 30.00:00:00)
- OverlapPeriod: time span (e.g., 7.00:00:00)
- SigningAlgorithm: RS256
- EncryptionAlgorithm: RSA-OAEP (use RSA-OAEP-256 if environment supports it)
- DisableAccessTokenEncryption: true (keeps current demo behavior; set false for encrypted access tokens)

Example
{
  "KeyManagement": {
    "Enabled": true,
    "SigningKeySize": 2048,
    "EncryptionKeySize": 2048,
    "RotationInterval": "30.00:00:00",
    "OverlapPeriod": "7.00:00:00",
    "SigningAlgorithm": "RS256",
    "EncryptionAlgorithm": "RSA-OAEP",
    "DisableAccessTokenEncryption": true
  }
}

## Lifecycle & Rotation Policy
States per key
- Created: generated but not yet activated
- Active: can be used for issuance and published in JWKS
- Retiring: kept for validation and published in JWKS until RetireAt
- Retired: no longer used/published, kept for audit
- Revoked: immediately unusable, not published

Rotation sequence
1) New primary generated (Active) for given Use (sig/enc)
2) Previous primary switches to Retiring and gets RetireAt = now + OverlapPeriod
3) After RetireAt, Retiring -> Retired

Default intervals
- RotationInterval: 30 days
- OverlapPeriod: 7 days

## How It Fits In The OIDC Server
- Discovery endpoint includes JWKS with all Active + Retiring keys
- ID tokens and authorization codes are signed with the current primary signing key (sig)
- If access token encryption is enabled, access/refresh tokens are encrypted using the current encryption key (enc)
- Validation by clients/resource servers succeeds during rotation because the previous key remains advertised

## Startup & Environment Behavior
- Development/Production: EF Core migrations apply; keys created on first run, rotation runs in background
- Tests: Database uses EnsureCreatedAsync, not migrations; the key initializer still seeds keys so tests can issue tokens
- Fallback: If DB is unavailable at configure time, ephemeral RSA keys are created and used until DB is ready

## Operations
Manual rotation
- Temporarily decrease RotationInterval (or implement an admin operation) to force a new key, wait for JWKS propagation, then restore

Revocation
- Set Status = Revoked on a key to immediately prevent its use/publication
- Consider invalidating dependent sessions/tokens out of band if required

Backups & DR
- KeyMaterials contains private keys; protect backups accordingly
- Ensure DB encryption at rest and restricted access
- Run rotation in non-prod before changing intervals in production

## Security Considerations
- Protect DB at rest and restrict access to the KeyMaterials table
- Avoid exporting private keys to logs or telemetry
- Consider moving to HSM/KMS or DPAPI-protected columns in the next phase
- Consider ECDSA (P-256) keys where permitted (smaller JWKS, faster) in a future iteration
- Monitor for algorithm support across environments before switching to RSA-OAEP-256

## Troubleshooting
IDX10615: Encryption failed (RSA-OAEP-256)
- Cause: runtime crypto provider not supporting the requested algorithm, or disposed RSA handle
- Fix: use RSA-OAEP (broader support) or ensure RSA instances backing keys are alive; verify you did not dispose ephemeral keys

Discovery shows no keys
- Ensure migrations ran and KeyMaterials has Active/Retiring rows
- Check logs from KeyRotationHostedService and KeyManagementService

Tokens signed by old kid still validate
- Expected during overlap; key is in Retiring state and still published in JWKS until RetireAt

## File & Code Map
- Models/KeyMaterial.cs
- Options/KeyManagementOptions.cs
- Services/IKeyManagementService.cs
- Services/KeyManagementService.cs
- Services/KeyRotationHostedService.cs
- Services/OpenIddictServerCredentialsConfigurator.cs
- Extensions/ServiceCollectionExtensions.cs (service wiring)
- Data/ApplicationDbContext.cs (DbSet + indexes)
- Migrations/20250907130810_KeyManagement*.cs

## Future
- Move private key storage to KMS/HSM
- Add admin UI for key lifecycle (promote/revoke/manual rotate)
- Instrument metrics and audit logs (key created/rotated/retired)
- Support EC keys and JWK import/export
