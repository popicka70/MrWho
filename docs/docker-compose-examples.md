# Docker Compose Examples

Last updated: 2026-05-17

This repository uses a small set of overlay files rather than many separate deployment manifests.

If you are choosing between the base setup, TLS termination at a reverse proxy, Redis, production hardening, demos, or the separate source-build track, start with [deployment-paths.md](deployment-paths.md).

## Recommended Order

1. Start with `Base` for local or direct HTTPS deployments where the container holds the certificate.
2. Start with `TLS Termination Base` when public HTTPS is handled by a reverse proxy and the backend should run on HTTP only.
3. Add `Base + Redis Overlay` when you want Redis-backed distributed features.
4. Move to `Base + Production Overlay` when you need the hardened baseline.
5. Use the demos only after the issuer itself is healthy.

## Base

```bash
docker compose up -d
```

Use this when you want the smallest possible local or evaluation setup.

## TLS Termination Base

```bash
docker compose -f docker-compose.tls-termination.yml up -d
```

Use this when you want:

- public HTTPS terminated at a reverse proxy or load balancer
- an HTTP-only backend container
- no local PFX mounted into the container

Pair this with the forwarded-header variables in `.env`, especially the known proxy or known network settings.

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
docker compose -f docker-compose.tls-termination.yml -f docker-compose.redis.yml up -d
```

Use this when you want:

- Redis-backed distributed features
- lower database load under repeated token and metadata operations
- a path that stays on the published-image workflow without switching to source builds

## Base + Production Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
docker compose -f docker-compose.tls-termination.yml -f docker-compose.production.yml up -d
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
OIDC_PUBLIC_BASE_URL=https://auth.example.com

# Required when the container itself serves HTTPS.
CERT_PASSWORD=changeit

REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379,abortConnect=false

FORWARDED_HEADERS_KNOWN_PROXY_0=10.0.0.10
FORWARDED_HEADERS_ALLOWED_HOST_0=auth.example.com

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

If the proxy performs TLS termination and the backend should not hold a certificate, use `docker-compose.tls-termination.yml` as the base file.

## Multi-Tenancy Example

There is no single `MULTITENANCY_ENABLED` deployment flag in the current line. Multi-tenancy is governed by licensing and tenant provisioning. Public URLs use `/t/{slug}` when tenant scoping is active.
