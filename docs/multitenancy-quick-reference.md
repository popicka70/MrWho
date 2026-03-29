# MrWhoOidc Multi-Tenancy Quick Reference

Last updated: 2026-03-29

## Core Model

- multi-tenancy is controlled by the installed platform license
- tenant-scoped URLs use `/t/{slug}`
- the platform/default context remains the place for platform-admin operations

## URL Patterns

Single-tenant style:

```text
https://auth.example.com/.well-known/openid-configuration
```

Tenant-scoped style:

```text
https://auth.example.com/t/acme/.well-known/openid-configuration
https://auth.example.com/t/acme/authorize
https://auth.example.com/t/acme/token
```

## Default / Platform Context

Use the default context for:

- bootstrap
- platform-admin dashboard
- tenant creation
- tenant import/export
- impersonation into tenant admin contexts

## Tenant Context

Use tenant-scoped URLs for:

- user login
- client integrations
- tenant admin management
- tenant branding and provider configuration

## Operational Notes

- the issuer must match the tenant-scoped URL clients actually use
- reverse proxies must preserve the correct public host and scheme
- branding, providers, users, clients, and scopes are tenant-scoped
- platform admin is a distinct authorization surface, not just another tenant role name

## CLI Pattern

Typical CLI login in a tenant-scoped deployment:

```bash
mrwho-cli login --server https://auth.example.com/t/acme
```

See `mrwho-cli-guide.md` for examples.
