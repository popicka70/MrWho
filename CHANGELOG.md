# Changelog

All notable changes to MrWhoOidc will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-02

### Added

#### Core Features
- Full OpenID Connect 1.0 and OAuth 2.0 protocol support
- Authorization Code Flow with PKCE
- Client Credentials Flow
- Token Exchange (RFC 8693) with On-Behalf-Of support
- Refresh Token support with rotation
- DPoP (Demonstrating Proof-of-Possession) token binding
- Pushed Authorization Requests (PAR)
- JWT-Secured Authorization Request (JAR)
- JWT-Secured Authorization Response Mode (JARM)
- Back-Channel Logout with durable outbox pattern

#### Multi-Tenancy & Identity Federation
- Multi-tenant architecture with tenant isolation
- Tenant-specific branding (logos, colors, names)
- Identity Provider Chaining for social login and enterprise SSO
- Support for external OIDC providers (Google, Microsoft, Okta, etc.)
- Automatic discovery endpoint detection
- Provider key rotation support

#### Security
- Argon2id password hashing
- Client secret rotation with zero-downtime (up to 3 active secrets)
- Client secret expiry monitoring and metrics
- Comprehensive audit logging with PII hashing
- JWKS endpoint with automatic key rotation
- Rate limiting and circuit breaker patterns
- TLS/HTTPS enforcement

#### Performance & Scalability
- Optional Redis caching (30-50% faster response times)
- 60-80% reduction in database load with Redis
- Distributed session storage
- Health check endpoints
- OpenTelemetry support for observability

#### Admin UI
- Client management (create, update, delete, secrets)
- User management
- Scope configuration
- Provider configuration
- Tenant management
- Key rotation interface
- Audit log viewing

#### Deployment
- Docker Compose deployment (3 variants: basic, redis, production)
- PostgreSQL 16 database
- Multi-architecture Docker images (amd64, arm64)
- Automated TLS certificate generation scripts
- Environment-based configuration
- Health endpoints for monitoring
- Graceful shutdown support

#### Developer Tools
- **Demo Applications:**
  - .NET 9 MVC confidential client demo
  - React + Vite public client demo (browser-based PKCE)
  - Go confidential client demo
  - All demos include Docker Compose integration

- **NuGet Packages:**
  - `MrWhoOidc.Client` 0.1.0 - Discovery, authorization, token exchange helpers
  - `MrWhoOidc.Security` 0.1.0 - DPoP, PKCE, JWT validation utilities

- **Documentation:**
  - Quick Start Guide (< 10 minute setup)
  - Admin Guide
  - Developer Guide with integration examples
  - Deployment Guide (Docker Compose variants)
  - Configuration Reference (all environment variables)
  - Troubleshooting Guide
  - Multi-tenancy Quick Reference
  - Key Rotation Playbook
  - Docker Security Best Practices
  - Upgrade Guide

#### Testing & Quality
- Comprehensive unit test suite
- Integration tests for OIDC flows
- E2E tests with DPoP validation
- Token exchange test coverage
- Client secret rotation tests

### Documentation

- Complete README.md with feature overview, quick start, and deployment options
- 10 detailed documentation files covering all aspects
- 3 demo READMEs with troubleshooting sections
- NuGet package documentation with code examples
- Version compatibility matrix

### Infrastructure

- GitHub Container Registry (GHCR) publishing
- Automated Docker builds
- Multi-stage Docker builds for optimization
- PostgreSQL with connection pooling
- Redis with RDB persistence and LRU eviction

### Security Considerations

- Self-signed certificates supported for development
- CA-signed certificates required for production
- Client secrets required for confidential clients
- PKCE required for public clients
- Secure session cookie configuration
- CORS protection
- CSRF protection for admin UI

### Known Limitations

- Single database instance (no built-in read replicas)
- Redis clustering not configured (single instance)
- Multi-tenant strict validation partially implemented
- mTLS for backchannel logout not yet implemented
- RP strict validation for backchannel logout in progress

### Breaking Changes

- N/A (initial release)

### Migration Notes

- N/A (initial release)

---

## Release Notes

### Version 1.0.0

This is the initial public release of MrWhoOidc. The server has been tested in development and staging environments. For production deployment:

1. Use CA-signed TLS certificates
2. Enable Redis caching for better performance
3. Use strong database and certificate passwords
4. Review security best practices in documentation
5. Monitor health endpoints
6. Enable structured logging
7. Configure rate limiting appropriately

### Upgrading

Not applicable for initial release. Future upgrade guides will be provided in documentation.

### Support

- **Issues**: https://github.com/popicka70/mrwhooidc/issues
- **Discussions**: https://github.com/popicka70/mrwhooidc/discussions
- **Documentation**: https://github.com/popicka70/mrwhooidc/tree/main/docs

---

[1.0.0]: https://github.com/popicka70/mrwhooidc/releases/tag/v1.0.0
