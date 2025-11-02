# GitHub Repository Metadata

## Repository Description

```
Production-ready OpenID Connect (OIDC) Identity Provider built on .NET 9. Deploy in minutes with Docker Compose. Multi-tenant, high-performance, standards-compliant.
```

## Topics/Tags

```
oidc
openid-connect
oauth2
identity-provider
authorization-server
authentication
dotnet
csharp
aspnetcore
docker
docker-compose
postgresql
redis
multi-tenant
dpop
pkce
jwt
dotnet9
identity
security
```

## About Section

**Website**: (To be added after deployment)

**Topics**: oidc, openid-connect, oauth2, identity-provider, authorization-server, authentication, dotnet, csharp, aspnetcore, docker, docker-compose, postgresql, redis, multi-tenant, security

## Repository Settings

### General

- **Description**: Production-ready OpenID Connect (OIDC) Identity Provider built on .NET 9. Deploy in minutes with Docker Compose. Multi-tenant, high-performance, standards-compliant.
- **Website**: (Optional - add after deploying documentation site)
- **Topics**: (See above - max 20 topics)
- **Include in the home page**: ✅ Checked
- **Releases**: ✅ Enabled
- **Packages**: ✅ Enabled (for GitHub Container Registry)
- **Deployments**: ❌ Disabled (unless using GitHub Environments)
- **Environments**: ❌ Disabled

### Features

- **Wikis**: ❌ Disabled (documentation in /docs)
- **Issues**: ✅ Enabled
- **Sponsorships**: ❌ Disabled (optional for future)
- **Preserve this repository**: ❌ Disabled
- **Discussions**: ✅ Enabled (for community Q&A)
- **Projects**: ❌ Disabled (using Issues for tracking)

### Pull Requests

- **Allow merge commits**: ✅ Enabled
- **Allow squash merging**: ✅ Enabled (default)
- **Allow rebase merging**: ✅ Enabled
- **Always suggest updating pull request branches**: ✅ Enabled
- **Automatically delete head branches**: ✅ Enabled

### Security

- **Security policy**: ✅ Enabled (SECURITY.md exists)
- **GitHub Advanced Security**: ❌ Disabled (public repo, optional)
- **Dependency graph**: ✅ Enabled (automatic for public repos)
- **Dependabot alerts**: ✅ Enabled
- **Dependabot security updates**: ✅ Enabled
- **Dependabot version updates**: ✅ Enabled (create dependabot.yml)
- **Secret scanning**: ✅ Enabled (automatic for public repos)

### Social Preview Image

Recommended size: 1280×640px  
Suggested content:
- MrWhoOidc logo/name
- Tagline: "Production-Ready OpenID Connect Identity Provider"
- Key features: ".NET 9", "Docker", "Multi-Tenant", "High Performance"
- QR code to repository (optional)

## README Badges

Already included in README.md:
- Docker badge
- License badge (MIT)
- .NET 9 badge
- PostgreSQL badge
- Multi-Arch badge

Suggested additional badges:
- ![GitHub release](https://img.shields.io/github/v/release/popicka70/mrwhooidc?style=for-the-badge)
- ![GitHub issues](https://img.shields.io/github/issues/popicka70/mrwhooidc?style=for-the-badge)
- ![GitHub stars](https://img.shields.io/github/stars/popicka70/mrwhooidc?style=for-the-badge)

## Initial Release

### Pre-Release Checklist

- [x] Version 1.0.0 tagged
- [x] CHANGELOG.md created
- [x] README.md complete with Quick Start
- [x] LICENSE file present
- [x] SECURITY.md present with reporting process
- [ ] CONTRIBUTING.md created (T072)
- [ ] Issue templates created (T071)
- [x] Documentation complete (docs/)
- [x] Demo applications ready (demos/)
- [x] NuGet packages documented (packages/)
- [x] Docker images published to GHCR
- [x] All tests passing

### Release Announcement

**Title**: MrWhoOidc 1.0.0 - Production-Ready OpenID Connect Identity Provider

**Body**:
```
We're excited to announce the first public release of MrWhoOidc!

🎉 **What's New**

MrWhoOidc is a production-ready OpenID Connect (OIDC) and OAuth 2.0 authorization server built on .NET 9. Get up and running in under 10 minutes with Docker Compose.

✨ **Key Features**

- Full OIDC 1.0 & OAuth 2.0 support
- Multi-tenant architecture
- Optional Redis caching (30-50% faster)
- DPoP & PKCE support
- Back-Channel Logout
- Built-in Admin UI
- 3 demo applications (.NET, React, Go)
- NuGet packages for .NET integration

🚀 **Quick Start**

```bash
git clone https://github.com/popicka70/mrwhooidc.git
cd mrwhooidc
./scripts/generate-cert.sh localhost changeit
cp .env.example .env
# Edit .env with your passwords
docker compose up -d
```

📚 **Documentation**

- [Quick Start Guide](README.md#-quick-start)
- [Demo Applications](demos/README.md)
- [NuGet Packages](packages/README.md)
- [Deployment Guide](docs/deployment-guide.md)

🐛 **Known Issues**

See [CHANGELOG.md](CHANGELOG.md) for known limitations and future roadmap.

📦 **Docker Images**

Available at `ghcr.io/popicka70/mrwhooidc:1.0.0` (amd64, arm64)

---

Full release notes: [CHANGELOG.md](CHANGELOG.md)
```
