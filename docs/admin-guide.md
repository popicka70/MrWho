# MrWhoOidc Admin Guide

Last updated: 2026-03-29

This guide summarizes the current administration model exposed by MrWhoOidc.

## Two Administrative Contexts

### Tenant Admin

Tenant admins work inside a tenant context and manage tenant-scoped resources such as:

- realms
- clients
- scopes
- roles
- users
- external providers
- provider keys and claim mappings
- branding and tenant settings
- back-channel logout client configuration

### Platform Admin

Platform admins work from the platform/default context and manage cross-tenant operations such as:

- tenant creation and lifecycle
- tenant import/export workflows
- impersonation into tenant admin contexts
- platform-wide settings and licensing

See `platform-admin-guide.md` for the dedicated platform-admin surface.

## Common Tenant Admin Workflows

### Clients

Manage:

- redirect URIs and logout URIs
- PKCE requirements
- PAR/JAR/JARM-related settings
- client secret rotation
- OBO / token exchange permissions
- device authorization and CIBA eligibility where applicable

### External Providers

Tenant admins can configure external identity providers and related metadata such as:

- authority / discovery URLs
- client credentials
- PKCE, JAR, and PAR preferences
- claim mapping
- provider keys and rotation

### Keys and Signing

Administration includes:

- viewing current signing keys
- rotating active signing keys
- verifying `kid` publication through JWKS

### Back-Channel Logout

Back-channel logout configuration is client-specific. Ensure each relying party exposes a reachable back-channel logout URI before enabling the feature.

### Rate Limits and Audit

Current product surfaces include rate-limit inspection and structured audit logging. Treat these as operational signals rather than end-user features.

## Recommended Operational Practices

- separate platform-admin access from tenant-admin access
- avoid using the same admin account for day-to-day tenant work and platform maintenance
- rotate confidential client secrets regularly
- validate redirect/logout URIs exactly
- review provider and key configuration changes through audit logs
