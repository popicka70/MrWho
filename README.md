# MrWhoOidc Public Repository

This repository is the public-facing companion to the MrWhoOidc product line.

It exists to publish:

- deployment guidance
- public configuration and operations documentation
- demo applications
- .NET client packages
- a lightweight GitHub Pages site

## What Is In This Repo

| Area | Purpose |
|---|---|
| [docs](docs) | deployment guides, configuration reference, admin and developer docs, operational guides |
| [demos](demos) | working example applications in .NET, React, Go, Kotlin, plus an OBO demo API |
| [src/MrWhoOidc.Client](src/MrWhoOidc.Client) | .NET client package for discovery, auth flows, token exchange, logout helpers, and JWKS caching |
| [src/MrWhoOidc.Security](src/MrWhoOidc.Security) | .NET security helpers including DPoP support |
| [docker-compose.yml](docker-compose.yml) | base container deployment |
| [docker-compose.dev.yml](docker-compose.dev.yml) | local development overlay with MailHog |
| [docker-compose.redis.yml](docker-compose.redis.yml) | Redis performance overlay |
| [docker-compose.production.yml](docker-compose.production.yml) | hardened production overlay |
| [website](website) | static GitHub Pages site for the project overview |

## Current Platform Scope

MrWhoOidc currently focuses on a standards-based OIDC and OAuth 2.0 identity service with current product capabilities including:

- Authorization Code + PKCE
- Client Credentials
- Token Exchange / on-behalf-of
- Refresh token rotation
- PAR, JAR, and JARM
- DPoP
- Device Authorization
- CIBA
- Back-channel logout
- WebAuthn and passkeys
- tenant admin and platform admin surfaces
- CLI-based administration with `mrwho-cli`

## Quick Start

### Prerequisites

- Docker Engine 20.10+ and Docker Compose V2+
- a TLS certificate in `certs/aspnetapp.pfx` for local testing
- 4 GB RAM minimum for a comfortable local environment

The examples below use `docker compose`. If your environment still exposes the legacy `docker-compose` binary, replace the command name accordingly. First run is typically 3-5 minutes, depending on image pulls and container startup time.

The base `docker-compose.yml` path is production-oriented. On an empty database it does not auto-seed a tenant or admin user; the first usable local instance requires an explicit bootstrap.

### Local Container Startup

```bash
git clone https://github.com/popicka70/MrWho.git
cd MrWho

bash ./scripts/generate-cert.sh localhost changeit

cp .env.example .env
# edit POSTGRES_PASSWORD, CERT_PASSWORD, and OIDC_PUBLIC_BASE_URL
# on a fresh local database, also set BOOTSTRAP_TOKEN to a temporary value

docker compose up -d

# bootstrap the first tenant and admin user on an empty database
curl -k -X POST https://localhost:8443/bootstrap \
	-H 'Content-Type: application/json' \
	-H 'X-Bootstrap-Token: your-temporary-bootstrap-token' \
	-d '{
		"tenantSlug": "default",
		"tenantName": "Default Tenant",
		"adminEmail": "admin@example.com",
		"adminPassword": "ChangeMeNow123!",
		"adminName": "Administrator"
	}'

# remove BOOTSTRAP_TOKEN from .env after the bootstrap succeeds,
# then re-apply the containers
docker compose up -d

# post-bootstrap smoke tests
curl -k https://localhost:8443/t/default/.well-known/openid-configuration
curl -k -I https://localhost:8443/admin/clients
curl -k https://localhost:8443/t/default/jwks
bash ./scripts/health-check.sh https://localhost:8443 default
```

Expected discovery output includes fields such as `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri`.

Expected first-run behavior:

- `https://localhost:8443/admin/clients` redirects anonymous users to the tenant login page.
- The tenant-scoped discovery document is the primary local smoke test.
- Remove `BOOTSTRAP_TOKEN` after the initial bootstrap so `POST /bootstrap` is no longer available.

Optional overlays:

```bash
# Development logging + MailHog
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Add Redis caching
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d

# Hardened production-style setup
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

Default endpoints:

- discovery: `https://localhost:8443/t/default/.well-known/openid-configuration`
- admin UI: `https://localhost:8443/admin/clients`
- tenant JWKS: `https://localhost:8443/t/default/jwks`
- root JWKS: `https://localhost:8443/jwks`

Use the tenant-scoped discovery document for first-run smoke tests. Root discovery depends on a default tenant already existing.

For fresh production-style databases, set `BOOTSTRAP_TOKEN` and follow [docs/deployment-guide.md](docs/deployment-guide.md).

## Documentation Map

Start here depending on what you need:

- [Deployment guide](docs/deployment-guide.md)
- [Configuration reference](docs/configuration-reference.md)
- [Docker Compose examples](docs/docker-compose-examples.md)
- [Developer guide](docs/developer-guide.md)
- [Admin guide](docs/admin-guide.md)
- [Multi-tenancy quick reference](docs/multitenancy-quick-reference.md)
- [mrwho-cli guide](docs/mrwho-cli-guide.md)
- [Advanced flows guide](docs/advanced-flows-guide.md)
- [WebAuthn guide](docs/webauthn-guide.md)
- [Platform admin guide](docs/platform-admin-guide.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Upgrade guide](docs/upgrade-guide.md)
- [Docker security best practices](docs/docker-security-best-practices.md)

## Example Applications

See [demos/README.md](demos/README.md) for the full matrix. Highlights:

- `.NET Razor client` for interactive confidential-client scenarios
- `React SPA` for browser-only PKCE flows
- `Go web client` for non-.NET web integrations
- `Kotlin Spring client` for Java and Spring environments
- `OBO demo API` for delegated token validation patterns

## .NET Packages

The public client packages currently published from this repo are:

| Package | Current Line | Targets |
|---|---|---|
| `MrWhoOidc.Client` | `2.0.1` | `net8.0`, `net10.0` |
| `MrWhoOidc.Security` | `2.0.1` | `net8.0`, `net10.0` |

These packages are intended to make client integration, discovery, token handling, DPoP, and logout processing easier for .NET applications.

## Multi-Tenancy Notes

Current public documentation reflects the product’s current behavior:

- multi-tenancy is controlled by the installed platform license
- tenant-scoped URLs use `/t/{slug}`
- platform-admin operations are performed from the default or platform context
- tenant administration remains isolated to the tenant context

See [docs/multitenancy-quick-reference.md](docs/multitenancy-quick-reference.md) for the operational model.

## GitHub Pages

This repo ships a small static site in [website](website) intended for GitHub Pages deployment. The Pages workflow lives in [.github/workflows/deploy-pages.yml](.github/workflows/deploy-pages.yml).

## Contact

- Public repository: [github.com/popicka70/MrWho](https://github.com/popicka70/MrWho)
- Contact: [info@mrwhooidc.com](mailto:info@mrwhooidc.com)
