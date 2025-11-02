# MrWhoOidc - OpenID Connect Identity Provider

[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://github.com/popicka70/mrwhooidc/pkgs/container/mrwhooidc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![.NET 9](https://img.shields.io/badge/.NET-9-512BD4?style=for-the-badge&logo=dotnet)](https://dotnet.microsoft.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-316192?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![Multi-Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-blue?style=for-the-badge)](https://github.com/popicka70/mrwhooidc/pkgs/container/mrwhooidc)

**MrWhoOidc** is a production-ready OpenID Connect (OIDC) and OAuth 2.0 authorization server built on .NET 9. Deploy in minutes using Docker Compose for secure authentication and authorization across your applications and APIs.

## ✨ Key Features

- **🔐 Standards-Compliant OIDC/OAuth 2.0** - Full OpenID Connect and OAuth 2.0 support including Authorization Code Flow, Client Credentials, Token Exchange, and more
- **⚡ High Performance** - Optional Redis caching for 30-50% faster response times and 60-80% reduction in database load
- **🏢 Multi-Tenant Ready** - Support multiple organizations with isolated data and branding
- **🔗 Identity Provider Chaining** - Enable social login and enterprise SSO by integrating with external identity providers
- **🔒 Enhanced Security** - DPoP (Demonstrating Proof-of-Possession), PKCE, token binding, back-channel logout, and comprehensive audit logging
- **🎯 Easy Deployment** - Deploy in under 10 minutes with Docker Compose; no complex infrastructure required
- **📊 Built-in Admin UI** - Manage clients, users, scopes, and configuration through intuitive web interface
- **🔧 Extensible Architecture** - NuGet packages for .NET integration; RESTful APIs for custom integrations
- **📈 Observability Ready** - Structured logging, health endpoints, and OpenTelemetry support
- **🐳 Container-Native** - Optimized Docker images with multi-architecture support (amd64, arm64)

## � Version Compatibility

| Component | Version | Status | Notes |
|-----------|---------|--------|-------|
| **MrWhoOidc Server** | 1.0.0 | ✅ Stable | Initial public release |
| **Docker Image** | `ghcr.io/popicka70/mrwhooidc:latest` | ✅ Production | Multi-arch (amd64, arm64) |
| **PostgreSQL** | 16.x | ✅ Recommended | Minimum: 14.x |
| **Redis** | 7.2.x | ✅ Recommended | Optional, for caching |
| **.NET Runtime** | 9.0 | ✅ Required | Server runtime |
| **MrWhoOidc.Client** | 0.1.0 | ✅ Stable | .NET 8.0+ |
| **MrWhoOidc.Security** | 0.1.0 | ✅ Stable | .NET 8.0+ |

**NuGet Package Compatibility:**

- **MrWhoOidc.Client 0.1.0** → Works with MrWhoOidc Server 1.0.0+
- **MrWhoOidc.Security 0.1.0** → Framework-agnostic, works with any OIDC server
- Both packages target **.NET 8.0** and are compatible with .NET 8.0, 9.0+

**Docker Image Tags:**

- `latest` - Latest stable release (currently 1.0.0)
- `1.0.0` - Specific version tag
- `1.0` - Major.minor tag (receives patch updates)

## �🚀 Quick Start

Get MrWhoOidc up and running in **under 10 minutes**.

### Prerequisites

- **Docker** 20.10+ and **Docker Compose** V2+
- **4GB RAM** minimum (8GB recommended for production)
- **TLS Certificate** (self-signed for development, CA-signed for production)

### Installation Steps

#### 1. Clone and Navigate

```bash
# Clone the repository
git clone https://github.com/popicka70/mrwhooidc.git
cd mrwhooidc
```

#### 2. Generate TLS Certificate

```bash
# Generate self-signed certificate for development
chmod +x scripts/generate-cert.sh
./scripts/generate-cert.sh localhost changeit

# This creates: certs/aspnetapp.pfx
```

**Windows (PowerShell):**

```powershell
# Use Git Bash or WSL to run the script
bash scripts/generate-cert.sh localhost changeit
```

#### 3. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set REQUIRED variables:
# - POSTGRES_PASSWORD=your-secure-database-password
# - CERT_PASSWORD=changeit
# - OIDC_PUBLIC_BASE_URL=https://localhost:8443
```

**Minimum .env configuration:**

```bash
# Database
POSTGRES_PASSWORD=YourSecurePassword123!

# TLS Certificate
CERT_PASSWORD=changeit

# OIDC Configuration
OIDC_PUBLIC_BASE_URL=https://localhost:8443
```

#### 4. Start Services

```bash
# Start MrWhoOidc and PostgreSQL
docker compose up -d

# Wait for services to initialize (30-60 seconds)
# Check logs
docker compose logs -f mrwho-oidc
```

**Expected output:**

```text
mrwho-oidc       | info: Microsoft.Hosting.Lifetime[14]
mrwho-oidc       |       Now listening on: https://[::]:8443
mrwho-oidc       | info: Microsoft.Hosting.Lifetime[14]
mrwho-oidc       |       Now listening on: http://[::]:8080
```

#### 5. Verify Deployment

```bash
# Run health check script
chmod +x scripts/health-check.sh
./scripts/health-check.sh https://localhost:8443
```

**Access the services:**

- **OpenID Discovery**: <https://localhost:8443/.well-known/openid-configuration>
- **Admin UI**: <https://localhost:8443/admin>
- **Health Endpoint**: <https://localhost:8443/health>

**Default admin credentials** (⚠️ **CHANGE IMMEDIATELY**):

- Username: `admin`
- Password: `Admin123!`

🎉 **Success!** Your OIDC provider is now running.

### Next Steps

1. **Change default admin password** in Admin UI → User Management
2. **Register your first client** in Admin UI → Client Management
3. **Configure your application** to use MrWhoOidc for authentication
4. **Review security settings** in `.env` file
5. **Explore documentation** in `/docs` directory

## 📦 Features

### Core OIDC & OAuth 2.0

- **Authorization Code Flow** with PKCE (Proof Key for Code Exchange)
- **Client Credentials Flow** for service-to-service authentication
- **Token Exchange** (RFC 8693) for delegation and impersonation scenarios
- **Refresh Tokens** with rotation support
- **JWT Access Tokens** with customizable claims
- **OpenID Connect Discovery** for automatic client configuration
- **JWKS (JSON Web Key Set)** endpoint for token signature verification
- **Token Revocation** (RFC 7009)
- **Token Introspection** (RFC 7662)

### Enterprise Features

- **Multi-Tenancy** - Isolated tenant data with custom branding and configuration
- **High Performance** - Redis caching reduces response time by 30-50%
- **Observability** - Structured logging, health checks, metrics, and OpenTelemetry integration
- **Audit Logging** - Comprehensive audit trail for security and compliance
- **Client Secret Rotation** - Zero-downtime secret rotation with multi-secret support
- **Back-Channel Logout** - Centralized logout across multiple applications
- **DPoP (Demonstrating Proof-of-Possession)** - Enhanced token security with cryptographic binding
- **Scalability** - Horizontal scaling support with Redis session sharing

### Identity Provider Chaining

- **External Identity Providers** - Integrate with social logins (Google, Microsoft, GitHub, etc.)
- **Enterprise SSO** - Connect to SAML 2.0 and WS-Federation identity providers
- **Identity Brokering** - Act as intermediary between clients and upstream identity providers
- **Account Linking** - Link multiple external identities to single user account

## 🐳 Docker Deployment

### Pull from GitHub Container Registry

```bash
# Pull the latest version
docker pull ghcr.io/popicka70/mrwhooidc:latest

# Pull specific version
docker pull ghcr.io/popicka70/mrwhooidc:v1.0.0
```

### Docker Compose Variants

MrWhoOidc provides three deployment configurations using the Docker Compose overlay pattern. Each variant extends the base `docker-compose.yml` with additional features:

#### 1. Basic (Default) - `docker-compose.yml`

**Best for:** Development, evaluation, small deployments (<1000 users)

```bash
docker compose up -d
```

**Includes:**

- MrWhoOidc OIDC Provider
- PostgreSQL 16 database
- TLS/HTTPS support
- Health checks
- Minimal resource usage (2GB RAM)

**Use when:** Getting started, testing, small-scale deployments, or when performance/security requirements are minimal.

---

#### 2. High-Performance - `docker-compose.redis.yml`

**Best for:** Production deployments requiring high performance (1000-10,000 users)

```bash
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d
```

**Adds to basic:**

- **Redis 7.2** caching layer
  - 30-50% faster response times
  - 60-80% reduction in database load
  - Distributed session storage for horizontal scaling
- RDB persistence with 60-second snapshot interval
- LRU eviction policy (512MB memory limit)
- Health checks and monitoring

**Configuration:**

```bash
# .env additions
REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379
```

**Use when:** High traffic expected, performance is critical, horizontal scaling needed, or reduced database load desired.

**Performance gains:**

- Discovery endpoint: 800ms → 250ms
- Token validation: 150ms → 50ms
- Client lookup: 100ms → 20ms

---

#### 3. Production-Hardened - `docker-compose.production.yml`

**Best for:** Production with security requirements, regulated environments, enterprise deployments

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

**Adds to basic:**

- **Redis caching** (all performance benefits from redis.yml)
- **Security hardening:**
  - Non-root containers (UID 1000 for app, UID 999 for PostgreSQL)
  - Read-only root filesystems with tmpfs for writable paths
  - Linux capability management (drop ALL, add only NET_BIND_SERVICE)
  - no-new-privileges security option
- **Multi-tenant mode** enabled
- **Rate limiting** (100 requests/60s per IP)
- **Enhanced security headers** (CORS, HSTS, CSP)
- **Resource limits:**
  - CPU: 2 cores (burst to 4)
  - Memory: 2GB (limit 4GB)
- **Redis authentication** (password-protected)
- **Audit logging** enabled
- **Enhanced health checks** (30s interval, 3 retries)
- **Network isolation** (internal network for database/Redis)

**Configuration:**

```bash
# .env additions (required)
REDIS_ENABLED=true
REDIS_CONNECTION_STRING=mrwho-redis:6379
REDIS_PASSWORD=your-secure-redis-password
MULTITENANT_ENABLED=true
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_WINDOW=100
RATE_LIMIT_WINDOW_SECONDS=60
AUDIT_LOGGING_ENABLED=true
```

**Use when:** Production deployment, security compliance required, multi-tenant scenarios, regulated industries, or enterprise environments.

**Pre-deployment checklist:**

- [ ] Change all default passwords
- [ ] Use CA-signed TLS certificate
- [ ] Configure SMTP for email notifications
- [ ] Set strong Redis password
- [ ] Review and adjust resource limits
- [ ] Configure backup strategy
- [ ] Set up monitoring/alerting
- [ ] Review CORS allowed origins

---

#### 4. Development - `docker-compose.dev.yml`

**Best for:** Local development, testing email workflows, debugging

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

**Adds to basic:**

- **MailHog** email testing service
  - Web UI: http://localhost:8025
  - SMTP: localhost:1025
  - Captures all outbound emails for inspection
- Development environment settings:
  - Detailed error messages
  - Debug-level logging
  - Relaxed CORS (allow any origin)
  - No rate limiting
  - Sensitive data logging enabled
  - HTTP allowed (no forced HTTPS redirect)

**Configuration:**

```bash
# .env additions
ASPNETCORE_ENVIRONMENT=Development
MAIL_ENABLED=true
MAIL_SMTP_HOST=mailhog
MAIL_SMTP_PORT=1025
MAIL_FROM_ADDRESS=noreply@localhost
LOGGING_LEVEL=Debug
```

**Use when:** Developing applications, testing email flows (password reset, verification), debugging authentication issues, or learning OIDC workflows.

⚠️ **Never use dev configuration in production** - it disables critical security features.

---

### Choosing the Right Variant

| Scenario | Variant | Command |
|----------|---------|---------|
| Quick start, evaluation, testing | Basic | `docker compose up -d` |
| Development with email testing | Dev | `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d` |
| Production with high performance | Redis | `docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d` |
| Production with security hardening | Production | `docker compose -f docker-compose.yml -f docker-compose.production.yml up -d` |
| Enterprise/regulated environments | Production | `docker compose -f docker-compose.yml -f docker-compose.production.yml up -d` |

**Can I combine variants?** No - variants are mutually exclusive. Choose the one that best matches your requirements.

**Migration path:**

1. Start with **Basic** for evaluation
2. Move to **Dev** for application development
3. Deploy **Redis** for production performance
4. Upgrade to **Production** when security hardening required

See [docs/docker-compose-examples.md](docs/docker-compose-examples.md) for detailed configuration examples and [docs/deployment-guide.md](docs/deployment-guide.md) for production deployment best practices.

### Essential Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_PASSWORD` | ✅ Yes | - | PostgreSQL database password (min 16 chars) |
| `CERT_PASSWORD` | ✅ Yes | - | TLS certificate password |
| `OIDC_PUBLIC_BASE_URL` | ✅ Yes | - | Public URL where users access the IdP (e.g., `https://auth.example.com`) |
| `ASPNETCORE_ENVIRONMENT` | No | `Production` | Environment: `Development`, `Staging`, `Production` |
| `MULTITENANT_ENABLED` | No | `false` | Enable multi-tenant mode |
| `REDIS_ENABLED` | No | `false` | Enable Redis caching (requires Redis service) |
| `MAIL_ENABLED` | No | `false` | Enable email notifications (requires SMTP config) |
| `LOGGING_LEVEL` | No | `Information` | Log level: `Trace`, `Debug`, `Information`, `Warning`, `Error`, `Critical` |
| `ADMIN_UI_ENABLED` | No | `true` | Enable admin UI at `/admin` |

**Security Notes:**

- **Never use default passwords in production**
- **Use strong passwords** (min 16 characters, mixed case, numbers, symbols)
- **Rotate secrets regularly** (90-day rotation recommended)
- **Use CA-signed certificates** in production (not self-signed)
- **Restrict admin UI access** with firewall rules or disable if using API management

See [.env.example](.env.example) for complete documentation of all 60+ environment variables.

### Container Images

Images are available for multiple architectures:

- **linux/amd64** - x86-64 processors (Intel, AMD)
- **linux/arm64** - ARM64 processors (Apple M1/M2, AWS Graviton, Raspberry Pi 4+)

Automatic architecture detection - Docker selects the correct image for your platform.

## 🔧 Configuration

### Complete Configuration Guide

- **[Deployment Guide](docs/deployment-guide.md)** - Production deployment best practices
- **[Docker Security](docs/docker-security-best-practices.md)** - Container security hardening
- **[Configuration Reference](docs/configuration-reference.md)** - Complete environment variable reference
- **[Multi-Tenancy](docs/multitenancy-quick-reference.md)** - Multi-tenant configuration
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

### Upgrading

See [docs/upgrade-guide.md](docs/upgrade-guide.md) for version migration and rollback procedures.

## 🐛 Troubleshooting

### Common Issues

#### 1. Port Conflict - "Address already in use"

**Cause:** Another service is using ports 8443 or 8081.

**Solution:**

```bash
# Check what's using the ports
# Linux/macOS
sudo lsof -i :8443
sudo lsof -i :8081

# Windows
netstat -ano | findstr :8443

# Change ports in .env
OIDC_HTTPS_PORT=9443
OIDC_HTTP_PORT=9081
```

#### 2. Database Connection Failed

**Cause:** PostgreSQL not ready or incorrect credentials.

**Solution:**

```bash
# Check PostgreSQL health
docker compose ps mrwho-postgres

# View PostgreSQL logs
docker compose logs mrwho-postgres

# Verify POSTGRES_PASSWORD in .env matches
# Wait 30-60 seconds for PostgreSQL initialization
```

#### 3. Certificate Errors - "The SSL connection could not be established"

**Cause:** Missing or incorrect TLS certificate configuration.

**Solution:**

```bash
# Verify certificate exists
ls -la certs/aspnetapp.pfx

# Regenerate certificate
./scripts/generate-cert.sh localhost changeit

# Verify CERT_PASSWORD in .env matches generation password
# Ensure certificate is mounted in docker-compose.yml (should be default)
```

#### 4. Database Migrations Failed

**Cause:** Database schema not initialized or upgrade failed.

**Solution:**

```bash
# View application logs for specific error
docker compose logs mrwho-oidc | grep -i migration

# Reset database (⚠️ DESTROYS ALL DATA)
docker compose down -v
docker compose up -d

# For production upgrades, see docs/upgrade-guide.md
```

#### 5. Missing Required Environment Variables

**Cause:** `.env` file missing or incomplete.

**Solution:**

```bash
# Copy template if missing
cp .env.example .env

# Verify required variables are set
cat .env | grep -E "POSTGRES_PASSWORD|CERT_PASSWORD|OIDC_PUBLIC_BASE_URL"

# Edit .env and set all REQUIRED variables
# See .env.example for required vs optional variables
```

### Additional Help

- **Check container status**: `docker compose ps`
- **View logs**: `docker compose logs -f mrwho-oidc`
- **Run health check**: `./scripts/health-check.sh`
- **Review configuration**: `docker compose config`
- **Community Support**: [File an issue](https://github.com/popicka70/mrwhooidc/issues)

For security vulnerabilities, please report privately (see [SECURITY.md](SECURITY.md)).

## � Integration & Demos

### Demo Applications

Get started quickly with complete working examples demonstrating MrWhoOidc integration in different technologies:

| Demo | Technology | Client Type | Use Case | Quick Start |
|------|-----------|-------------|----------|-------------|
| **[.NET MVC Client](demos/dotnet-mvc-client/)** | ASP.NET Core 9, Razor Pages | Confidential | Server-rendered web apps | [README](demos/dotnet-mvc-client/README.md) |
| **[React SPA Client](demos/react-client/)** | React 18, TypeScript, Vite | Public | Single-page applications | [README](demos/react-client/README.md) |
| **[Go Web Client](demos/go-client/)** | Go 1.21+, native libraries | Confidential | Go web apps, microservices | [README](demos/go-client/README.md) |

**Run any demo in under 5 minutes:**

```bash
# Example: .NET MVC Demo
cd demos/dotnet-mvc-client

# Start MrWhoOidc and demo together
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d

# Register client at https://localhost:8443/admin
# Configure client secret in .env
# Access demo at https://localhost:5001
```

See [demos/README.md](demos/README.md) for detailed guides, technology comparisons, and best practices.

### NuGet Packages

Official packages for .NET applications to integrate with MrWhoOidc:

#### MrWhoOidc.Client

OIDC client configuration helpers for discovery, JWKS, token validation.

```bash
dotnet add package MrWhoOidc.Client
```

**Basic Usage:**

```csharp
using MrWhoOidc.Client;

// Register services
services.AddMrWhoOidcClient(options =>
{
    options.Authority = "https://your-oidc-provider.com";
    options.ClientId = "your-client-id";
    options.ClientSecret = "your-client-secret";
});

// Use discovery service
public class MyService
{
    private readonly IDiscoveryService _discoveryService;
    
    public MyService(IDiscoveryService discoveryService)
    {
        _discoveryService = discoveryService;
    }
    
    public async Task<string> GetAuthorizationUrlAsync()
    {
        var discovery = await _discoveryService.GetDiscoveryDocumentAsync();
        return discovery.AuthorizationEndpoint;
    }
}
```

#### MrWhoOidc.Security

Security utilities for DPoP, PKCE, and JWT validation.

```bash
dotnet add package MrWhoOidc.Security
```

**PKCE Example:**

```csharp
using MrWhoOidc.Security.Pkce;

public class AuthController : ControllerBase
{
    private readonly IPkceGenerator _pkceGenerator;
    
    public AuthController(IPkceGenerator pkceGenerator)
    {
        _pkceGenerator = pkceGenerator;
    }
    
    public IActionResult Login()
    {
        // Generate PKCE parameters
        var codeVerifier = _pkceGenerator.GenerateCodeVerifier();
        var codeChallenge = _pkceGenerator.GenerateCodeChallenge(codeVerifier);
        
        // Store code_verifier in session for token exchange
        HttpContext.Session.SetString("code_verifier", codeVerifier);
        
        // Build authorization URL with code_challenge
        var authUrl = $"{authority}/authorize?" +
            $"client_id={clientId}&" +
            $"response_type=code&" +
            $"code_challenge={codeChallenge}&" +
            $"code_challenge_method=S256";
        
        return Redirect(authUrl);
    }
}
```

**Package Documentation:**

- **[Package Overview](packages/README.md)**: Installation, usage, version compatibility
- **[Integration Examples](packages/integration-examples.md)**: Authorization Code Flow, Token Exchange, DPoP, Logout
- **[NuGet Gallery](https://www.nuget.org/profiles/MrWho)**: Browse all published packages

## �📚 Documentation

### Quick Navigation

| Guide | Description |
|-------|-------------|
| **[Configuration Reference](docs/configuration-reference.md)** | Complete environment variable reference (60+ variables) |
| **[Troubleshooting Guide](docs/troubleshooting.md)** | Common issues and solutions with diagnostic commands |
| **[Deployment Guide](docs/deployment-guide.md)** | Production deployment best practices and procedures |
| **[Upgrade Guide](docs/upgrade-guide.md)** | Version migration, rollback, and compatibility matrix |
| **[Docker Compose Examples](docs/docker-compose-examples.md)** | Detailed docker-compose configurations for various scenarios |
| **[Docker Security Best Practices](docs/docker-security-best-practices.md)** | Container security hardening and compliance |
| **[Admin Guide](docs/admin-guide.md)** | Admin UI usage, client management, and configuration |
| **[Multi-Tenancy Quick Reference](docs/multitenancy-quick-reference.md)** | Multi-tenant setup and tenant isolation |
| **[Key Rotation Playbook](docs/key-rotation-playbook.md)** | Signing key rotation procedures |

### By Topic

#### 🚀 Getting Started

- **[Quick Start Guide](#-quick-start)** - Get running in 10 minutes (above)
- **[Configuration Reference](docs/configuration-reference.md)** - All environment variables explained
- **[Docker Compose Examples](docs/docker-compose-examples.md)** - Common deployment scenarios

#### 🏭 Production Deployment

- **[Deployment Guide](docs/deployment-guide.md)** - Production deployment checklist and best practices
- **[Docker Security Best Practices](docs/docker-security-best-practices.md)** - Security hardening
- **[Upgrade Guide](docs/upgrade-guide.md)** - Version upgrades and rollback procedures

#### 🛠️ Operations & Maintenance

- **[Troubleshooting Guide](docs/troubleshooting.md)** - Diagnose and fix common issues (15+ scenarios)
- **[Admin Guide](docs/admin-guide.md)** - Admin UI usage and client configuration
- **[Key Rotation Playbook](docs/key-rotation-playbook.md)** - Rotate signing keys safely

#### 🏢 Enterprise Features

- **[Multi-Tenancy Quick Reference](docs/multitenancy-quick-reference.md)** - Multi-tenant configuration
- **[Docker Security Best Practices](docs/docker-security-best-practices.md)** - Security hardening

#### 🔌 Integration

- **Demo Applications** - Working examples in `/demos` directory:
  - [dotnet-mvc-client](demos/dotnet-mvc-client/) - ASP.NET Core MVC integration
  - [react-client](demos/react-client/) - React SPA with oidc-client-ts
  - [go-client](demos/go-client/) - Go web application
- **NuGet Packages** - See [packages/README.md](packages/README.md)

### Common Tasks

<details>
<summary>🔍 Click to expand common tasks</summary>

#### Initial Setup

1. [Generate TLS certificate](#2-generate-tls-certificate) → See Quick Start above
2. [Configure environment variables](docs/configuration-reference.md#required-variables) → `cp .env.example .env`
3. [Start services](#4-start-services) → `docker compose up -d`
4. [Verify deployment](#5-verify-deployment) → `./scripts/health-check.sh`

#### Client Configuration

1. [Register client in Admin UI](docs/admin-guide.md#client-management) → https://localhost:8443/admin
2. [Configure redirect URIs](docs/admin-guide.md#redirect-uris) → Required for OIDC flow
3. [Assign scopes](docs/admin-guide.md#scope-assignment) → Define access permissions
4. [Generate client secret](docs/admin-guide.md#client-secrets) → Save securely

#### Performance Optimization

1. [Enable Redis caching](#2-high-performance---docker-composeredisyml) → 30-50% faster
2. [Configure resource limits](docs/docker-compose-examples.md#resource-limits) → CPU/memory tuning
3. [Monitor performance](docs/troubleshooting.md#performance-issues) → Diagnostic commands

#### Security Hardening

1. [Use production variant](#3-production-hardened---docker-composeproductionyml) → Security features
2. [Configure TLS properly](docs/deployment-guide.md#tls-configuration) → CA-signed certificate
3. [Enable rate limiting](docs/configuration-reference.md#security-configuration) → DDoS protection
4. [Review security checklist](docs/docker-security-best-practices.md) → Best practices

#### Troubleshooting

1. [Check service status](docs/troubleshooting.md#quick-diagnostics) → `docker compose ps`
2. [View logs](docs/troubleshooting.md#service-status) → `docker compose logs -f`
3. [Run health check](docs/troubleshooting.md#health-checks) → `./scripts/health-check.sh`
4. [Search issues](docs/troubleshooting.md#table-of-contents) → 15+ common scenarios

</details>

## 🔌 Integration

### Demo Applications

See working integration examples in the `/demos` directory:

- **[dotnet-mvc-client](demos/dotnet-mvc-client/)** - ASP.NET Core MVC with OIDC authentication
- **[react-client](demos/react-client/)** - React SPA with oidc-client-ts
- **[go-client](demos/go-client/)** - Go web application with OIDC

### NuGet Packages

.NET client libraries for easy integration:

- **MrWhoOidc.Client** - Client library for .NET applications
- **MrWhoOidc.Security** - DPoP and security utilities

See [packages/README.md](packages/README.md) for installation and usage.

## 🤝 Contributing

We welcome contributions! Here's how to get involved:

### Reporting Issues

- **Bug Reports**: [Open an issue](https://github.com/popicka70/mrwhooidc/issues/new?template=bug_report.md)
- **Feature Requests**: [Open an issue](https://github.com/popicka70/mrwhooidc/issues/new?template=feature_request.md)
- **Security Vulnerabilities**: See [SECURITY.md](SECURITY.md) for private reporting

### Contributing Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the coding standards
4. Write/update tests
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

**What this means:**

- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ℹ️ License and copyright notice required

## 🌐 Community & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/popicka70/mrwhooidc/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/popicka70/mrwhooidc/discussions)
- **Documentation**: [Full documentation](docs/)
- **Security**: [Report vulnerabilities](SECURITY.md)

## 🙏 Acknowledgments

Built with:

- [.NET 9](https://dotnet.microsoft.com/) - Modern, performant web framework
- [PostgreSQL](https://www.postgresql.org/) - Reliable relational database
- [Redis](https://redis.io/) - High-performance caching
- [Docker](https://www.docker.com/) - Container platform

---

**Ready to secure your applications?** [Get started](#-quick-start) in minutes.

**Have questions?** [Check the docs](docs/) or [open an issue](https://github.com/popicka70/mrwhooidc/issues).
