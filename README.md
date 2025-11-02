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

## 🚀 Quick Start

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

### Docker Compose Configurations

Three deployment configurations are available:

#### 1. Basic (Default) - `docker-compose.yml`

Best for: Development, evaluation, small deployments (<1000 users)

```bash
docker compose up -d
```

**Includes:**

- MrWhoOidc OIDC Provider
- PostgreSQL 16 database
- TLS/HTTPS support
- Health checks

#### 2. High-Performance - `docker-compose.redis.yml`

Best for: Production deployments requiring high performance

```bash
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d
```

**Adds:**

- Redis caching (30-50% faster response times)
- 60-80% reduction in database load
- Distributed session storage

#### 3. Production-Hardened - `docker-compose.production.yml`

Best for: Production with security requirements, regulated environments

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

**Adds:**

- Redis caching
- Multi-tenant mode
- Non-root containers
- Read-only volumes
- Network isolation
- Resource limits
- Enhanced health checks

See [docs/docker-compose-examples.md](docs/docker-compose-examples.md) for detailed configuration examples.

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
- **[Environment Variables](docs/environment-variables.md)** - Complete configuration reference
- **[Multi-Tenancy](docs/multi-tenancy-guide.md)** - Multi-tenant configuration
- **[Redis Caching](docs/hybrid-cache-guide.md)** - Performance optimization
- **[TLS/Certificates](docs/tls-certificate-guide.md)** - Certificate management

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

## 📚 Documentation

- **[Quick Start Guide](docs/quick-start.md)** - Detailed setup walkthrough
- **[Admin Guide](docs/admin-guide.md)** - Admin UI usage and client configuration
- **[Developer Guide](docs/developer-guide.md)** - Integration and API documentation
- **[Deployment Guide](docs/deployment-guide.md)** - Production deployment
- **[Security Best Practices](docs/docker-security-best-practices.md)** - Hardening
- **[Client Secret Rotation](docs/client-secret-rotation-playbook.md)** - Secret management
- **[Back-Channel Logout](docs/backchannel-logout-backlog.md)** - Logout implementation
- **[Architecture](docs/architecture.md)** - System design and components

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
