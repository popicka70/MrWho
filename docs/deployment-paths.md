# Deployment Paths

Last updated: 2026-05-17

This guide helps first-time operators choose the right Docker-based path in the `MrWho` repository.

If you only remember one rule, remember this one: follow one path at a time and do not mix `MrWho` published-image commands with `MrWhoOidc` source-build commands.

## Start Here

Use the `MrWho` repository when you want:

- the published Docker image path
- PostgreSQL-backed local or evaluation installs
- Redis and production compose overlays
- public demo applications after the issuer is running

Use the `MrWhoOidc` repository only when you need to build from source, modify code, or run contributor workflows.

## Scenario Matrix

| Path | Use this when | Primary command | What next |
|---|---|---|---|
| Prebuilt Setup | You want the smallest working local or evaluation install | `docker compose up -d` | Bootstrap, verify, then pick Redis, production, or demos |
| Proxy TLS Termination | Public HTTPS is terminated by your reverse proxy or load balancer and you do not want a local PFX in the backend container | `docker compose -f docker-compose.tls-termination.yml up -d` | Validate through the public proxy URL, then add Redis or production hardening if needed |
| Prebuilt + Redis | You want Redis-backed distributed features and lower database load | `docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d` | Validate Redis-backed deployment, then consider production hardening |
| Prebuilt + Production | You want the hardened baseline | `docker compose -f docker-compose.yml -f docker-compose.production.yml up -d` | Finish TLS, secrets, reverse proxy, and monitoring work |
| Prebuilt + Examples | You want real client integrations after bootstrap | Start the issuer once, then follow a demo README | Choose a demo by stack and flow |
| Source Build | You need local code changes, seeded dev data, or contributor workflows | Use the `MrWhoOidc` source-build guide instead of this repo | Stay on the source-build track |

## Prebuilt Setup

Use this path when you want the simplest possible install.

```bash
docker compose up -d
```

This path gives you:

- MrWhoOidc server
- PostgreSQL
- the standard bootstrap flow for a fresh production-style database

Start here before you add Redis, try demos, or move toward production hardening.

Primary references:

- [deployment-guide.md](deployment-guide.md)
- [docker-compose-examples.md](docker-compose-examples.md)

## Proxy TLS Termination

Use this path when a reverse proxy or load balancer presents the public HTTPS endpoint and the backend container should run on HTTP only.

```bash
docker compose -f docker-compose.tls-termination.yml up -d
```

This path is a good fit when you want:

- public HTTPS handled upstream
- forwarded headers to drive the correct request scheme and host inside the app
- no local `certs/aspnetapp.pfx` mounted into the backend container

Key rules for this path:

- set `OIDC_PUBLIC_BASE_URL` to the public `https://...` URL seen by clients
- configure `FORWARDED_HEADERS_KNOWN_PROXY_*` or `FORWARDED_HEADERS_KNOWN_NETWORK_*` whenever possible
- use `FORWARDED_HEADERS_UNSAFE_TRUST_ALL=true` only as a last resort on controlled infrastructure
- validate through the public proxy URL, not by treating the backend HTTP port as a public endpoint

You can still compose this path with the existing overlays:

```bash
docker compose -f docker-compose.tls-termination.yml -f docker-compose.redis.yml up -d
docker compose -f docker-compose.tls-termination.yml -f docker-compose.production.yml up -d
```

Primary references:

- [deployment-guide.md](deployment-guide.md)
- [docker-compose-examples.md](docker-compose-examples.md)

## Prebuilt + Redis

Use this path when the base deployment is already understood and you want Redis-backed distributed features.

```bash
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d
```

This path is a good fit when you want:

- lower PostgreSQL load under repeated token and metadata work
- a closer step toward the production overlay baseline
- Redis-backed distributed features without switching to the source-build track

Suggested validation:

```bash
docker compose ps
bash ./scripts/health-check.sh https://localhost:8443 default
```

Primary references:

- [docker-compose-examples.md](docker-compose-examples.md)
- [deployment-guide.md](deployment-guide.md)

## Prebuilt + Production

Use this path when you want the hardened compose overlay.

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

This path adds:

- Redis enabled by default
- hardened container settings
- JSON console logging
- resource limits and non-root users

You should still finish the operational work around TLS, secrets, backups, reverse proxy settings, and monitoring.

Primary reference:

- [deployment-guide.md](deployment-guide.md)

## Prebuilt + Examples

Use this path after the issuer is already running and verified.

Start the issuer once with the base deployment, then choose a demo that matches your goal:

- `.NET MVC` for the clearest confidential web app example
- `React` for a browser-only SPA using PKCE and PAR
- `obo-demo-api` for downstream API token validation
- `Go` or `Kotlin/Spring` when your target stack is not .NET

The main rule here is simple: do not start with the demos before the issuer itself is healthy.

Primary reference:

- [../demos/README.md](../demos/README.md)

## Separate Source-Build Track

This repository does not own the source-build contributor path.

Switch to the `MrWhoOidc` source-build track only when you need:

- local code changes
- seeded development data
- local image builds
- contributor workflows and debugging

Use the public source-build guide or the `MrWhoOidc` developer quickstart instead of mixing those commands into the published-image path.