# MrWhoOidc Configuration Reference

**Version**: 1.0.0  
**Last Updated**: November 2, 2025  
**Target Audience**: Operations engineers, DevOps teams, System administrators

Complete reference for all configuration options in MrWhoOidc. This document covers all environment variables organized by category.

## Table of Contents

1. [Core Configuration](#core-configuration)
2. [TLS/HTTPS Configuration](#tlshttps-configuration)
3. [OIDC Configuration](#oidc-configuration)
4. [Multi-Tenancy Configuration](#multi-tenancy-configuration)
5. [Redis Caching Configuration](#redis-caching-configuration)
6. [Email/SMTP Configuration](#emailsmtp-configuration)
7. [Logging Configuration](#logging-configuration)
8. [Security Configuration](#security-configuration)
9. [Admin UI Configuration](#admin-ui-configuration)
10. [Advanced Configuration](#advanced-configuration)

## Configuration Method

All configuration is done via environment variables in the `.env` file or directly in `docker-compose.yml`.

### Using .env File (Recommended)

```bash
# Copy template
cp .env.example .env

# Edit configuration
nano .env

# Start with configuration
docker compose up -d
```

### Configuration Priority

1. **docker-compose.yml environment section** (highest priority)
2. **.env file** (standard approach)
3. **System environment variables** (lowest priority)

## Core Configuration

Essential settings required for basic operation.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `ASPNETCORE_ENVIRONMENT` | string | No | `Production` | ASP.NET Core environment: `Development`, `Staging`, `Production`. Development enables detailed errors. |
| `ASPNETCORE_URLS` | string | No | `https://+:8443;http://+:8080` | URLs the application listens on. Format: `protocol://host:port`. Multiple separated by `;`. |
| `POSTGRES_PASSWORD` | string | **Yes** | - | PostgreSQL database password. **Use strong password (min 16 chars, mixed case, numbers, symbols)**. |
| `ConnectionStrings__authdb` | string | No | Auto-generated | Full PostgreSQL connection string. Usually auto-generated from POSTGRES_PASSWORD. |

**Example**:

```bash
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=https://+:8443;http://+:8080
POSTGRES_PASSWORD=MySecurePassword123!@#
```

## TLS/HTTPS Configuration

Certificate configuration for secure HTTPS connections.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `CERT_PASSWORD` | string | **Yes** | - | Password for PFX certificate file. Must match password used when generating certificate. |
| `ASPNETCORE_Kestrel__Certificates__Default__Path` | string | No | `/https/aspnetapp.pfx` | Path to PFX certificate file inside container. |
| `OIDC_HTTPS_PORT` | number | No | `8443` | Host port mapping for HTTPS. |
| `OIDC_HTTP_PORT` | number | No | `8081` | Host port mapping for HTTP (redirects to HTTPS). |

**Example**:

```bash
CERT_PASSWORD=changeit
ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetapp.pfx
OIDC_HTTPS_PORT=8443
OIDC_HTTP_PORT=8081
```

**Certificate Generation**:

```bash
./scripts/generate-cert.sh localhost changeit
```

## OIDC Configuration

OpenID Connect provider settings.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `OIDC_PUBLIC_BASE_URL` | string | **Yes** | - | Public URL where users access the OIDC provider. Must match actual URL. Examples: `https://localhost:8443`, `https://auth.example.com` |
| `Oidc__PublicBaseUrl` | string | **Yes** | - | Same as OIDC_PUBLIC_BASE_URL (alternate format). |

**Example**:

```bash
# Local development
OIDC_PUBLIC_BASE_URL=https://localhost:8443

# Production
OIDC_PUBLIC_BASE_URL=https://auth.example.com
```

**Important**: URL must be accessible to clients and match certificate CN/SAN.

## Multi-Tenancy Configuration

Settings for multi-tenant deployments supporting multiple organizations.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `MULTITENANT_ENABLED` | boolean | No | `false` | Enable multi-tenant mode. `true` = multiple tenants, `false` = single tenant. |
| `MULTITENANT_DEFAULT_TENANT_SLUG` | string | No | `default` | Default tenant identifier when tenant cannot be determined. |
| `MULTITENANT_STRATEGY` | string | No | `Host` | Tenant resolution strategy: `Host` (subdomain), `Path` (URL path), `Header` (HTTP header). |
| `MultiTenant__Enabled` | boolean | No | `false` | Same as MULTITENANT_ENABLED (alternate format). |
| `MultiTenant__DefaultTenantSlug` | string | No | `default` | Same as MULTITENANT_DEFAULT_TENANT_SLUG. |

**Example - Single Tenant**:

```bash
MULTITENANT_ENABLED=false
MULTITENANT_DEFAULT_TENANT_SLUG=default
```

**Example - Multi-Tenant with Subdomains**:

```bash
MULTITENANT_ENABLED=true
MULTITENANT_DEFAULT_TENANT_SLUG=default
MULTITENANT_STRATEGY=Host

# Tenants accessible at:
# - https://tenant1.auth.example.com
# - https://tenant2.auth.example.com
```

**Example - Multi-Tenant with Paths**:

```bash
MULTITENANT_ENABLED=true
MULTITENANT_STRATEGY=Path

# Tenants accessible at:
# - https://auth.example.com/tenant1
# - https://auth.example.com/tenant2
```

## Redis Caching Configuration

Optional Redis configuration for improved performance.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `REDIS_ENABLED` | boolean | No | `false` | Enable Redis caching. **Requires Redis service running**. |
| `REDIS_CONNECTION_STRING` | string | No | `mrwho-redis:6379,abortConnect=false` | Redis connection string. Format: `host:port,options`. |
| `REDIS_DATABASE` | number | No | `0` | Redis database number (0-15). |
| `REDIS_INSTANCE_NAME` | string | No | `mrwho` | Redis key prefix for this instance. |
| `REDIS_PASSWORD` | string | No | - | Redis password (if authentication enabled). |
| `Redis__Enabled` | boolean | No | `false` | Same as REDIS_ENABLED (alternate format). |
| `Redis__ConnectionString` | string | No | - | Same as REDIS_CONNECTION_STRING. |

**Example - Redis Disabled (Default)**:

```bash
REDIS_ENABLED=false
```

**Example - Redis Enabled**:

```bash
REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379,abortConnect=false
REDIS_DATABASE=0
REDIS_INSTANCE_NAME=mrwho-prod
```

**Example - Redis with Authentication**:

```bash
REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379,password=SecurePassword123,abortConnect=false
REDIS_PASSWORD=SecurePassword123
```

**Performance Impact**: 30-50% faster response times, 60-80% reduction in database load.

**Use with**:

```bash
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d
```

## Email/SMTP Configuration

Email notification settings for password resets, verifications, and alerts.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `MAIL_ENABLED` | boolean | No | `false` | Enable email functionality. Requires SMTP configuration when `true`. |
| `MAIL_SMTP_HOST` | string | Conditional | - | SMTP server hostname. Required when MAIL_ENABLED=true. |
| `MAIL_SMTP_PORT` | number | No | `587` | SMTP server port. Common: 587 (TLS), 465 (SSL), 25 (plain). |
| `MAIL_SMTP_USE_SSL` | boolean | No | `true` | Use SSL/TLS encryption for SMTP. |
| `MAIL_FROM_ADDRESS` | string | Conditional | - | Sender email address. Required when MAIL_ENABLED=true. |
| `MAIL_FROM_NAME` | string | No | `MrWhoOidc` | Sender display name. |
| `MAIL_SMTP_USERNAME` | string | Conditional | - | SMTP authentication username. Required for authenticated SMTP. |
| `MAIL_SMTP_PASSWORD` | string | Conditional | - | SMTP authentication password. Required for authenticated SMTP. |

**Example - Email Disabled (Default)**:

```bash
MAIL_ENABLED=false
```

**Example - Gmail SMTP**:

```bash
MAIL_ENABLED=true
MAIL_SMTP_HOST=smtp.gmail.com
MAIL_SMTP_PORT=587
MAIL_SMTP_USE_SSL=true
MAIL_FROM_ADDRESS=noreply@example.com
MAIL_FROM_NAME=My Identity Provider
MAIL_SMTP_USERNAME=your-gmail@gmail.com
MAIL_SMTP_PASSWORD=your-app-password
```

**Example - SendGrid SMTP**:

```bash
MAIL_ENABLED=true
MAIL_SMTP_HOST=smtp.sendgrid.net
MAIL_SMTP_PORT=587
MAIL_SMTP_USE_SSL=true
MAIL_FROM_ADDRESS=noreply@example.com
MAIL_FROM_NAME=My Identity Provider
MAIL_SMTP_USERNAME=apikey
MAIL_SMTP_PASSWORD=your-sendgrid-api-key
```

**Example - Development with MailHog**:

```bash
# Use docker-compose.dev.yml for MailHog
MAIL_ENABLED=true
MAIL_SMTP_HOST=mrwho-mailhog
MAIL_SMTP_PORT=1025
MAIL_SMTP_USE_SSL=false
MAIL_FROM_ADDRESS=noreply@mrwhooidc.local
```

## Logging Configuration

Application logging settings.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `LOGGING_LEVEL` | string | No | `Information` | Default log level: `Trace`, `Debug`, `Information`, `Warning`, `Error`, `Critical`. |
| `LOGGING_LEVEL_ASPNETCORE` | string | No | `Warning` | Log level for ASP.NET Core framework. |
| `Logging__LogLevel__Default` | string | No | `Information` | Same as LOGGING_LEVEL (alternate format). |
| `Logging__LogLevel__Microsoft.AspNetCore` | string | No | `Warning` | Same as LOGGING_LEVEL_ASPNETCORE. |
| `Logging__Console__FormatterName` | string | No | `simple` | Log format: `simple` (human-readable), `json` (structured). |

**Example - Production Logging**:

```bash
LOGGING_LEVEL=Information
LOGGING_LEVEL_ASPNETCORE=Warning
Logging__Console__FormatterName=json  # For log aggregation
```

**Example - Development Logging**:

```bash
LOGGING_LEVEL=Debug
LOGGING_LEVEL_ASPNETCORE=Information
Logging__Console__FormatterName=simple
```

**Log Levels**:

- `Trace`: Most detailed, includes all operations
- `Debug`: Detailed application flow
- `Information`: General information (recommended for production)
- `Warning`: Abnormal but handled situations
- `Error`: Errors and exceptions
- `Critical`: Critical failures

## Security Configuration

Security hardening options (primarily for production configuration).

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | string | No | - | Comma-separated list of allowed CORS origins. Example: `https://app1.com,https://app2.com` |
| `SECURITY_ENABLE_CSP` | boolean | No | `true` | Enable Content Security Policy headers. |
| `SECURITY_ENABLE_HSTS` | boolean | No | `true` | Enable HTTP Strict Transport Security. |
| `SECURITY_HSTS_MAX_AGE` | number | No | `31536000` | HSTS max-age in seconds (default: 1 year). |
| `RATELIMIT_ENABLED` | boolean | No | `true` | Enable rate limiting for API endpoints. |
| `RATELIMIT_PERMIT_LIMIT` | number | No | `100` | Maximum requests per time window. |
| `RATELIMIT_WINDOW` | number | No | `60` | Rate limit time window in seconds. |
| `AUDITLOG_ENABLED` | boolean | No | `true` | Enable comprehensive audit logging. |
| `AUDITLOG_INCLUDE_SENSITIVE` | boolean | No | `false` | Include sensitive data in audit logs. **Only use in development**. |

**Example - Production Security**:

```bash
CORS_ALLOWED_ORIGINS=https://myapp.example.com,https://admin.example.com
SECURITY_ENABLE_CSP=true
SECURITY_ENABLE_HSTS=true
SECURITY_HSTS_MAX_AGE=31536000
RATELIMIT_ENABLED=true
RATELIMIT_PERMIT_LIMIT=100
RATELIMIT_WINDOW=60
AUDITLOG_ENABLED=true
AUDITLOG_INCLUDE_SENSITIVE=false
```

## Admin UI Configuration

Settings for the administrative web interface.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `ADMIN_UI_ENABLED` | boolean | No | `true` | Enable admin UI at `/admin` endpoint. |
| `AdminUI__Enabled` | boolean | No | `true` | Same as ADMIN_UI_ENABLED (alternate format). |

**Example**:

```bash
# Enable admin UI (default)
ADMIN_UI_ENABLED=true

# Disable admin UI (use API management only)
ADMIN_UI_ENABLED=false
```

**Admin UI URL**: `https://your-domain:8443/admin`

**Default Credentials** (⚠️ change immediately):

- Username: `admin`
- Password: `Admin123!`

## Advanced Configuration

Advanced settings for specific scenarios.

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `SESSION_TIMEOUT` | number | No | `30` | Session timeout in minutes. |
| `SESSION_ABSOLUTE_TIMEOUT` | number | No | `480` | Absolute session timeout in minutes (forces re-authentication). |
| `CACHE_SESSION_DURATION` | number | No | `60` | Session cache duration in minutes (requires Redis). |
| `CACHE_TOKEN_DURATION` | number | No | `30` | Token cache duration in minutes (requires Redis). |
| `CACHE_DISCOVERY_DURATION` | number | No | `1440` | Discovery document cache duration in minutes (24 hours). |
| `DETAILED_ERRORS` | boolean | No | `false` | Show detailed errors in responses. **Only use in development**. |
| `HOT_RELOAD_ENABLED` | boolean | No | `false` | Enable hot reload for development. |
| `FORCE_HTTPS_REDIRECT` | boolean | No | `true` | Force HTTP to HTTPS redirect. |

**Example**:

```bash
SESSION_TIMEOUT=60
SESSION_ABSOLUTE_TIMEOUT=720
FORCE_HTTPS_REDIRECT=true
```

## Complete Configuration Examples

### Minimal Production Configuration

```bash
# Required settings only
POSTGRES_PASSWORD=YourSecurePassword123!@#$
CERT_PASSWORD=YourCertPassword123
OIDC_PUBLIC_BASE_URL=https://auth.example.com
```

### Complete Production Configuration

```bash
# Core
ASPNETCORE_ENVIRONMENT=Production
POSTGRES_PASSWORD=YourSecurePassword123!@#$

# TLS
CERT_PASSWORD=YourCertPassword123
OIDC_HTTPS_PORT=8443
OIDC_HTTP_PORT=8081

# OIDC
OIDC_PUBLIC_BASE_URL=https://auth.example.com

# Multi-Tenancy
MULTITENANT_ENABLED=true
MULTITENANT_DEFAULT_TENANT_SLUG=default

# Redis
REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379,abortConnect=false
REDIS_PASSWORD=SecureRedisPassword123

# Email
MAIL_ENABLED=true
MAIL_SMTP_HOST=smtp.sendgrid.net
MAIL_SMTP_PORT=587
MAIL_SMTP_USE_SSL=true
MAIL_FROM_ADDRESS=noreply@example.com
MAIL_SMTP_USERNAME=apikey
MAIL_SMTP_PASSWORD=your-sendgrid-api-key

# Logging
LOGGING_LEVEL=Information
Logging__Console__FormatterName=json

# Security
CORS_ALLOWED_ORIGINS=https://app.example.com
SECURITY_ENABLE_CSP=true
SECURITY_ENABLE_HSTS=true
RATELIMIT_ENABLED=true
AUDITLOG_ENABLED=true

# Admin UI
ADMIN_UI_ENABLED=true
```

### Development Configuration

```bash
# Core
ASPNETCORE_ENVIRONMENT=Development
POSTGRES_PASSWORD=DevPassword123

# TLS
CERT_PASSWORD=changeit

# OIDC
OIDC_PUBLIC_BASE_URL=https://localhost:8443

# Multi-Tenancy
MULTITENANT_ENABLED=false

# Redis
REDIS_ENABLED=false

# Email (MailHog)
MAIL_ENABLED=true
MAIL_SMTP_HOST=mrwho-mailhog
MAIL_SMTP_PORT=1025
MAIL_SMTP_USE_SSL=false
MAIL_FROM_ADDRESS=noreply@mrwhooidc.local

# Logging
LOGGING_LEVEL=Debug
LOGGING_LEVEL_ASPNETCORE=Information

# Development Features
DETAILED_ERRORS=true
HOT_RELOAD_ENABLED=true
FORCE_HTTPS_REDIRECT=false
CORS_ALLOW_ANY_ORIGIN=true
RATELIMIT_ENABLED=false
```

## Validation

### Check Configuration

```bash
# Validate docker-compose configuration
docker compose config

# View effective configuration
docker compose config | less

# Check specific service configuration
docker compose config mrwho-oidc
```

### Test Configuration

```bash
# Start services
docker compose up -d

# Check logs for configuration errors
docker compose logs mrwho-oidc | grep -i error

# Verify discovery endpoint
curl -k https://localhost:8443/.well-known/openid-configuration

# Run health check
./scripts/health-check.sh
```

## Troubleshooting Configuration

### Common Issues

**Missing Required Variables**:

```bash
# Error: "The 'POSTGRES_PASSWORD' variable is not set"
# Solution: Set in .env file
echo "POSTGRES_PASSWORD=YourPassword123" >> .env
```

**Certificate Errors**:

```bash
# Error: "The SSL connection could not be established"
# Solution: Regenerate certificate and verify password
./scripts/generate-cert.sh localhost changeit
# Ensure CERT_PASSWORD=changeit in .env
```

**URL Mismatch**:

```bash
# Error: "Issuer mismatch" in client applications
# Solution: Verify OIDC_PUBLIC_BASE_URL matches actual access URL
# Must match: protocol, domain, port
```

## See Also

- [Deployment Guide](deployment-guide.md) - Production deployment instructions
- [Docker Compose Examples](docker-compose-examples.md) - Configuration scenarios
- [Security Best Practices](docker-security-best-practices.md) - Security hardening
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
