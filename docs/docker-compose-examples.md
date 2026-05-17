# Docker Compose Examples

Last updated: 2026-05-17

This repository uses a small set of overlay files rather than many separate deployment manifests.

If you are choosing between the base setup, Redis, production hardening, demos, or the separate source-build track, start with [deployment-paths.md](deployment-paths.md).

## Recommended Order

1. Start with `Base` for the first bootstrap and verification.
2. Add `Base + Redis Overlay` when you want Redis-backed distributed features.
3. Move to `Base + Production Overlay` when you need the hardened baseline.
4. Use the demos only after the issuer itself is healthy.

## Base

```bash
docker compose up -d
```

Use this when you want the smallest possible local or evaluation setup.

## Base + Development Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Use this when you want:

- MailHog
- debug-oriented logging
- email workflow testing

## Base + Redis Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d
```

Use this when you want:

- Redis-backed distributed features
- lower database load under repeated token and metadata operations
- a path that stays on the published-image workflow without switching to source builds

## Base + Production Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

Use this when you want:

- Redis enabled by default
- hardened container settings
- structured JSON logs
- resource limits and non-root users

This is the next step after the base or Redis path when you want the production-minded compose baseline.

## Example `.env`

```bash
POSTGRES_PASSWORD=super-secret-password
CERT_PASSWORD=changeit
OIDC_PUBLIC_BASE_URL=https://auth.example.com

REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379,abortConnect=false

MAIL_ENABLED=true
MAIL_SMTP_HOST=smtp.example.com
MAIL_SMTP_PORT=587
MAIL_SMTP_USE_SSL=true
MAIL_FROM_ADDRESS=no-reply@example.com
MAIL_FROM_NAME=MrWhoOidc
MAIL_SMTP_USERNAME=smtp-user
MAIL_SMTP_PASSWORD=smtp-password
```

## Reverse Proxy Example

If the service is behind a reverse proxy or cloud ingress, keep `OIDC_PUBLIC_BASE_URL` aligned with the public HTTPS URL and configure forwarded-header variables in `.env`.

## Multi-Tenancy Example

There is no single `MULTITENANCY_ENABLED` deployment flag in the current line. Multi-tenancy is governed by licensing and tenant provisioning. Public URLs use `/t/{slug}` when tenant scoping is active.
