# MrWhoOidc Deployment Guide

Last updated: 2026-05-17

This guide covers the public Docker-based deployment assets in this repository.

If you are still deciding between the base install, Redis, production hardening, examples, or the separate source-build track, start with [deployment-paths.md](deployment-paths.md) first.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose V2+
- PostgreSQL storage capacity appropriate for your environment
- either a TLS certificate mounted as `certs/aspnetapp.pfx` or a reverse proxy / load balancer that terminates TLS upstream

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

For a scenario chooser with `use this when` guidance, see [deployment-paths.md](deployment-paths.md).

### Base

```bash
docker compose up -d
```

Includes:

- MrWhoOidc server
- PostgreSQL

This base expects the backend container itself to serve HTTPS with a mounted PFX.

### TLS Termination Base

```bash
docker compose -f docker-compose.tls-termination.yml up -d
```

Includes:

- MrWhoOidc server listening on HTTP only inside the container
- PostgreSQL
- forwarded-header support for a reverse proxy or load balancer that presents public HTTPS
- no local certificate mount in the backend container

Use this when the public `https://...` endpoint lives at the proxy and the backend should stay on private HTTP.

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

You can compose this overlay on top of either `docker-compose.yml` or `docker-compose.tls-termination.yml`.

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

You can compose this overlay on top of either `docker-compose.yml` or `docker-compose.tls-termination.yml`.

## TLS Termination Without Local Certificate

When a reverse proxy or cloud load balancer terminates TLS before traffic reaches the container, use the dedicated base file instead of the default `docker-compose.yml` path:

```bash
docker compose -f docker-compose.tls-termination.yml up -d
```

This deployment mode changes the backend assumptions:

- Kestrel listens on HTTP only at `:8080`
- the public URL must still be configured as `https://...` via `OIDC_PUBLIC_BASE_URL`
- the proxy must forward `X-Forwarded-Proto`, `X-Forwarded-Host`, and client IP information
- no `certs/aspnetapp.pfx` mount and no `CERT_PASSWORD` are required for this file

Recommended `.env` choices for this path:

- `OIDC_PUBLIC_BASE_URL=https://auth.example.com`
- `FORWARDED_HEADERS_KNOWN_PROXY_*` or `FORWARDED_HEADERS_KNOWN_NETWORK_*` set to trusted proxy values
- `FORWARDED_HEADERS_ENFORCE_HOST_ALLOW_LIST=true` when practical
- `FORWARDED_HEADERS_ALLOWED_HOST_0=auth.example.com` when practical

Use `FORWARDED_HEADERS_UNSAFE_TRUST_ALL=true` only when proxy IP ranges are not stable and the backend is not directly reachable by clients.

You can still layer the existing overlays on top of this base:

```bash
docker compose -f docker-compose.tls-termination.yml -f docker-compose.redis.yml up -d
docker compose -f docker-compose.tls-termination.yml -f docker-compose.production.yml up -d
```

Validation for this mode is different from the local PFX path:

- validate through the public HTTPS URL exposed by the proxy
- do not treat direct backend HTTP requests as a full end-to-end test of the deployment
- confirm discovery and redirect URLs resolve to the public HTTPS host, not to backend HTTP addresses

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

If you intentionally deployed with `docker-compose.tls-termination.yml`, this certificate warning should not apply because that base does not configure a local PFX.

## Reverse Proxy Notes

If you deploy behind a cloud load balancer or reverse proxy, review the forwarded-header variables in `.env.example`.

The safest approach is:

- keep `FORWARDED_HEADERS_UNSAFE_TRUST_ALL=false`
- provide known proxies or networks explicitly when possible
- ensure `OIDC_PUBLIC_BASE_URL` matches the externally visible HTTPS URL
- use `docker-compose.tls-termination.yml` when TLS ends at the proxy and the backend should not hold a local certificate

## Multi-Tenancy

Multi-tenancy is controlled by the installed platform license, not by a simple deployment toggle. Tenant-scoped endpoints use `/t/{slug}`.

See `multitenancy-quick-reference.md`.

## Recommended Production Baseline

- CA-signed certificate on the app itself, or trusted TLS termination at an upstream proxy
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
- proxy-terminated deployments emit public `https://...` URLs rather than backend `http://...` URLs
