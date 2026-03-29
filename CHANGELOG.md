# Changelog

All notable changes to the public MrWhoOidc repository are documented here.

## [2.0.1] - 2026-03-29

### Changed

- Updated public documentation from the original .NET 9 / `1.0.0` launch snapshot to the current .NET 10 product line.
- Updated package metadata for `MrWhoOidc.Client` and `MrWhoOidc.Security` to `2.0.1`.
- Retargeted the public .NET sample client to `net10.0`.
- Updated CI to build and publish with .NET 10.
- Refreshed Docker Compose and `.env` examples to match current configuration keys, bootstrap behavior, forwarded-header settings, and Redis usage.

### Added

- Current public documentation for:
  - CLI administration (`mrwho-cli`)
  - advanced flows (PAR, JAR, JARM, DPoP, device authorization, CIBA)
  - WebAuthn / passkeys
  - platform-admin operations
- Static GitHub Pages site assets under `website/`.

### Removed

- Internal planning and implementation-status documents that were not appropriate as long-lived public documentation.

## [1.0.0] - 2025-11-02

### Added

- Initial public release of the deployment assets, demo applications, documentation, and .NET client packages.

[2.0.1]: https://github.com/popicka70/MrWho/releases
[1.0.0]: https://github.com/popicka70/MrWho/releases/tag/v1.0.0
