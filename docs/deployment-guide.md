# MrWhoOidc Deployment Guide

Last updated: 2026-03-29

This guide covers the public Docker-based deployment assets in this repository.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose V2+
- PostgreSQL storage capacity appropriate for your environment
- a TLS certificate mounted as `certs/aspnetapp.pfx`

## Quick Start

```bash
git clone https://github.com/popicka70/MrWho.git
cd MrWho

bash ./scripts/generate-cert.sh localhost changeit
cp .env.example .env

# edit at minimum:
# POSTGRES_PASSWORD
# CERT_PASSWORD
# OIDC_PUBLIC_BASE_URL
# BOOTSTRAP_TOKEN on a fresh empty database

docker compose up -d

curl -k -X POST https://localhost:8443/bootstrap \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: ${BOOTSTRAP_TOKEN}" \
  -d '{
    "tenantSlug": "default",
    "tenantName": "Default Tenant",
    "adminEmail": "admin@example.com",
    "adminPassword": "ChangeMeNow123!",
    "adminName": "Administrator"
  }'

# remove BOOTSTRAP_TOKEN from .env after bootstrap, then re-apply
docker compose up -d
```

Check the deployment:

```bash
curl -k https://localhost:8443/t/default/.well-known/openid-configuration
curl -k -I https://localhost:8443/admin/clients
curl -k https://localhost:8443/t/default/jwks
bash ./scripts/health-check.sh https://localhost:8443 default
```

## Deployment Modes

### Base

```bash
docker compose up -d
```

Includes:

- MrWhoOidc server
- PostgreSQL

### Development Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Adds:

- MailHog
- development logging
- SMTP capture for testing mail flows

### Redis Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d
```

Adds:

- Redis-backed distributed features
- lower load on PostgreSQL under repeated token and metadata workloads

### Production Overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

Adds:

- Redis enabled by default
- read-only root filesystems where practical
- non-root container users
- capability reduction and resource limits
- JSON console logging

## First-Time Bootstrap

For a fresh production-style database, define `BOOTSTRAP_TOKEN` before startup. After the containers are healthy, call the bootstrap endpoint once:

```bash
curl -k -X POST https://localhost:8443/bootstrap \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: ${BOOTSTRAP_TOKEN}" \
  -d '{
    "tenantSlug": "default",
    "tenantName": "Default Tenant",
    "adminEmail": "admin@example.com",
    "adminPassword": "ChangeMeNow123!",
    "adminName": "Administrator"
  }'
```

After the initial bootstrap succeeds, remove `BOOTSTRAP_TOKEN` from `.env` and re-apply the containers so bootstrap is no longer exposed.

Post-bootstrap smoke tests for a fresh local install:

- discovery: `https://localhost:8443/t/default/.well-known/openid-configuration`
- admin UI: `https://localhost:8443/admin/clients`
- tenant JWKS: `https://localhost:8443/t/default/jwks`
- root JWKS: `https://localhost:8443/jwks`

Anonymous requests to `https://localhost:8443/admin/clients` should redirect to the tenant login page before an administrator signs in.

## Reverse Proxy Notes

If you deploy behind a cloud load balancer or reverse proxy, review the forwarded-header variables in `.env.example`.

The safest approach is:

- keep `FORWARDED_HEADERS_UNSAFE_TRUST_ALL=false`
- provide known proxies or networks explicitly when possible
- ensure `OIDC_PUBLIC_BASE_URL` matches the externally visible HTTPS URL

## Multi-Tenancy

Multi-tenancy is controlled by the installed platform license, not by a simple deployment toggle. Tenant-scoped endpoints use `/t/{slug}`.

See `multitenancy-quick-reference.md`.

## Recommended Production Baseline

- CA-signed certificate
- Redis enabled
- strong `POSTGRES_PASSWORD`
- `BOOTSTRAP_TOKEN` removed after initial use
- restricted forwarded-header trust
- external monitoring for health and logs
- regular PostgreSQL backups

## Validation Checklist

After deployment, verify:

- discovery document resolves correctly
- admin UI loads over HTTPS and resolves to login for anonymous users
- tenant JWKS resolves correctly
- tokens issued by the server contain the expected issuer and audience values
- mail delivery works if `MAIL_ENABLED=true`
- Redis is reachable when enabled
