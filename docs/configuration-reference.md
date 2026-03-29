# MrWhoOidc Configuration Reference

Last updated: 2026-03-29

This document summarizes the environment variables and configuration keys used by the public Docker deployment assets.

## Core Required Settings

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | yes | password for the bundled PostgreSQL container |
| `OIDC_PUBLIC_BASE_URL` | yes | public base URL exposed to users and clients |
| `CERT_PASSWORD` | yes | password for the TLS PFX mounted into the container |

## Bootstrap

| Variable | Required | Description |
|---|---|---|
| `BOOTSTRAP_TOKEN` | optional | one-time token for first production bootstrap on an empty database |

Use `BOOTSTRAP_TOKEN` only for initial setup. Remove it after the first successful bootstrap.

## Runtime

| Variable | Default | Description |
|---|---|---|
| `ASPNETCORE_ENVIRONMENT` | `Production` | runtime mode |
| `LOGGING_LEVEL` | `Information` | application log verbosity |
| `LOGGING_LEVEL_ASPNETCORE` | `Warning` | ASP.NET Core framework log verbosity |

## Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_ENABLED` | `false` | enables Redis-backed distributed features |
| `REDIS_CONNECTION_STRING` | `redis:6379,abortConnect=false` | StackExchange.Redis connection string |
| `REDIS_DATABASE` | `0` | logical Redis database |
| `REDIS_INSTANCE_NAME` | `mrwho` / `mrwho-prod` | key prefix for the current deployment |

Redis is recommended for production and larger environments.

## Mail / SMTP

| Variable | Default | Description |
|---|---|---|
| `MAIL_ENABLED` | `false` | enables mail sending |
| `MAIL_SMTP_HOST` | empty | SMTP host |
| `MAIL_SMTP_PORT` | `587` | SMTP port |
| `MAIL_SMTP_USE_SSL` | `true` | whether SMTP uses SSL/TLS |
| `MAIL_FROM_ADDRESS` | empty | sender address |
| `MAIL_FROM_NAME` | `MrWhoOidc` | sender display name |
| `MAIL_SMTP_USERNAME` | empty | SMTP username |
| `MAIL_SMTP_PASSWORD` | empty | SMTP password |

## Forwarded Headers / Reverse Proxy

| Variable | Default | Description |
|---|---|---|
| `FORWARDED_HEADERS_ENABLED` | `true` | enables forwarded-header processing |
| `FORWARDED_HEADERS_REQUIRE_HEADER_SYMMETRY` | `false` | stricter header validation |
| `FORWARDED_HEADERS_FORWARD_LIMIT` | `1` | max forward hops |
| `FORWARDED_HEADERS_UNSAFE_TRUST_ALL` | `false` | trust all proxies; only for controlled environments |
| `FORWARDED_HEADERS_ENFORCE_HOST_ALLOW_LIST` | `false` | validate forwarded host against allow-list |
| `FORWARDED_HEADERS_ALLOWED_HOST_0..2` | empty | allowed forwarded hosts |
| `FORWARDED_HEADERS_KNOWN_PROXY_0..2` | empty | trusted proxy IPs |
| `FORWARDED_HEADERS_KNOWN_NETWORK_0..1` | empty | trusted proxy CIDR ranges |

## Native Configuration Keys

If you run the server outside the provided Docker assets, the corresponding hierarchical keys are the same keys used inside the containers, for example:

- `ConnectionStrings__authdb`
- `Oidc__PublicBaseUrl`
- `Bootstrap__Token`
- `Redis__Enabled`
- `Redis__ConnectionString`
- `ForwardedHeaders__Enabled`

## Multi-Tenancy Note

Multi-tenancy is controlled by the installed platform license. It is not enabled by a simple deployment toggle in the public compose files.
