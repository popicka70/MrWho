# MrWhoOidc Deployment Guide

Last updated: 2026-05-16

This guide covers the public Docker-based deployment assets in this repository.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose V2+
- PostgreSQL storage capacity appropriate for your environment
- a TLS certificate mounted as `certs/aspnetapp.pfx`

The command examples below use `docker compose`. If your host still uses the legacy standalone binary, replace it with `docker-compose`. A first local run typically takes 3-5 minutes, depending on image pulls and startup time.

This guide is for the published Docker image path in the `MrWho` repository. Do not clone `MrWhoOidc` and do not replace `docker compose up -d` with `docker compose -f docker-compose.yml up -d --build` while following this guide.

## Quick Start

```bash
mkdir -p "$HOME/src"
cd "$HOME/src"

git clone https://github.com/popicka70/MrWho.git
cd MrWho

bash ./scripts/generate-cert.sh localhost changeit
chmod 644 ./certs/aspnetapp.pfx
cp .env.example .env

# for the stock local path, edit at minimum:
# POSTGRES_PASSWORD
# BOOTSTRAP_TOKEN on a fresh empty database
# CERT_PASSWORD=changeit and OIDC_PUBLIC_BASE_URL=https://localhost:8443 already match the generated certificate and default local ports
# leave MAIL_* empty unless you plan to enable SMTP
# if you are reusing an existing local Docker volume and changed POSTGRES_PASSWORD,
# either keep the original password or reset the local database state first:
# docker compose down -v --remove-orphans

grep -q 'ghcr.io/popicka70/mrwhooidc:latest' docker-compose.yml && echo "published image compose file confirmed"
docker compose config | grep ghcr.io/popicka70/mrwhooidc:latest

docker compose up -d

# if the first bootstrap curl fails with a TLS or socket error,
# wait 5-10 seconds for HTTPS startup and retry the same request

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

If the image verification commands do not print `ghcr.io/popicka70/mrwhooidc:latest`, stop because you are not using the published Docker image compose path.

If `MrWho` already exists locally and you want a clean first-run test, clone into a different persistent directory or intentionally clean the existing checkout first so you do not mix old `.env`, `certs/`, or Docker state into the evaluation.

Check the deployment:

```bash
curl -k https://localhost:8443/t/default/.well-known/openid-configuration
curl -k -I https://localhost:8443/admin/clients
curl -k https://localhost:8443/t/default/jwks
bash ./scripts/health-check.sh https://localhost:8443 default
```

Expected discovery output includes fields such as `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri`.

If you open `https://localhost:8443/admin` in a browser before trusting the generated local certificate, expect the normal self-signed certificate warning.

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

If `mrwho-oidc` logs show `password authentication failed for user "oidc"` and PostgreSQL logs say the database directory already exists or initialization was skipped, the local PostgreSQL volume was created with different credentials. PostgreSQL only applies `POSTGRES_PASSWORD` when the data directory is first initialized. Either restore the previous password in `.env` or reset the local Docker state with `docker compose down -v --remove-orphans`, then start again.

If `mrwho-oidc` logs show `Configured HTTPS certificate file '/https/aspnetapp.pfx' was not found`, the container never saw the expected TLS certificate mount. Regenerate it with `bash ./scripts/generate-cert.sh localhost changeit`, run `chmod 644 ./certs/aspnetapp.pfx` on Linux/macOS, confirm `./certs:/https:ro` is still present in `docker-compose.yml`, then restart the stack.

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
