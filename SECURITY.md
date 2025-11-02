# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in MrWhoOidc, please report it privately.

**Please do NOT create a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisories** (Preferred):
   - Visit [https://github.com/popicka70/mrwhooidc/security/advisories/new](https://github.com/popicka70/mrwhooidc/security/advisories/new)
   - Create a private security advisory
   - Provide detailed information about the vulnerability

2. **Email**:
   - Send an email to: [security@mrwhooidc.dev](mailto:security@mrwhooidc.dev)
   - Include "SECURITY" in the subject line
   - Encrypt sensitive information using our PGP key (available upon request)

### What to Include

To help us understand and address the issue quickly, please include:

- **Type of vulnerability** (e.g., OIDC protocol bypass, authentication bypass, injection, XSS, CSRF, etc.)
- **Full paths of affected source files**
- **Step-by-step instructions to reproduce** the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact assessment** - How an attacker might exploit this
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours of your report
- **Status Updates**: Every 7 days until resolved
- **Resolution**: Security patches are prioritized and typically released within 14-30 days depending on severity

### Disclosure Policy

- We ask that you give us reasonable time to fix the vulnerability before public disclosure
- We will credit you in release notes (unless you prefer to remain anonymous)
- We may request a coordinated disclosure timeline for critical vulnerabilities

## Security Best Practices

When deploying MrWhoOidc, follow these security best practices:

### Production Deployment

1. **Use CA-Signed TLS Certificates**
   - Never use self-signed certificates in production
   - Enable HTTPS for all endpoints
   - See [docs/deployment-guide.md](docs/deployment-guide.md)

2. **Secure Secrets Management**
   - Use strong passwords for `POSTGRES_PASSWORD` and `CERT_PASSWORD`
   - Rotate client secrets regularly
   - Never commit secrets to version control
   - Use secret management tools (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager)

3. **Network Security**
   - Place PostgreSQL and Redis on private networks
   - Use firewalls to restrict access
   - Enable TLS for Redis connections
   - Review [docs/docker-security-best-practices.md](docs/docker-security-best-practices.md)

4. **Database Security**
   - Use strong database passwords (20+ characters, mixed case, special chars)
   - Limit database user permissions (don't use superuser)
   - Enable PostgreSQL SSL connections
   - Regularly backup database with encryption

5. **Rate Limiting & DDoS Protection**
   - Configure rate limiting for token endpoints
   - Use a reverse proxy (nginx, Traefik) with rate limiting
   - Monitor for unusual traffic patterns
   - See configuration options in [docs/configuration-reference.md](docs/configuration-reference.md)

6. **Logging & Monitoring**
   - Enable structured logging
   - Monitor authentication failures
   - Alert on unusual access patterns
   - Regularly review audit logs
   - Never log client secrets or refresh tokens

7. **Regular Updates**
   - Keep Docker images up to date
   - Monitor security advisories
   - Test updates in staging before production
   - Subscribe to [GitHub Security Advisories](https://github.com/popicka70/mrwhooidc/security/advisories)

8. **Client Configuration**
   - Require PKCE for public clients
   - Use strong client secrets for confidential clients
   - Limit redirect URIs to exact matches
   - Review scopes assigned to clients
   - Implement token replay protection

### Known Security Considerations

- **Self-Signed Certificates**: Only use for development/testing, never production
- **Default Passwords**: Change all default passwords in `.env` file
- **Admin UI Access**: Restrict access to admin UI via firewall or authentication
- **Token Storage**: Clients should store tokens securely (never in localStorage for sensitive apps)
- **Backchannel Logout**: mTLS for backchannel logout endpoints not yet implemented (planned for future release)

### Security Features

MrWhoOidc includes these security features:

- ✅ **PKCE** (Proof Key for Code Exchange) - Required for public clients
- ✅ **DPoP** (Demonstrating Proof-of-Possession) - Token binding support
- ✅ **Argon2id** - Strong password hashing
- ✅ **Client Secret Rotation** - Zero-downtime secret rotation (up to 3 active secrets)
- ✅ **Audit Logging** - Comprehensive security event logging with PII hashing
- ✅ **Token Expiry** - Configurable token lifetimes
- ✅ **Refresh Token Rotation** - Automatic rotation on use
- ✅ **Back-Channel Logout** - Centralized logout with durable outbox
- ✅ **Rate Limiting** - Protection against brute-force attacks
- ✅ **CORS Protection** - Configurable cross-origin policies

### Security Testing

We recommend:

- **Penetration Testing** before production deployment
- **Vulnerability Scanning** of Docker images and dependencies
- **OIDC Compliance Testing** using standard test suites
- **Load Testing** to identify DDoS resilience

### Compliance

MrWhoOidc is designed to support:

- **OIDC 1.0 Compliance**
- **OAuth 2.0 Security Best Practices** (RFC 8252, RFC 8628, etc.)
- **GDPR** - PII handling and user data management
- **SOC 2** - Audit logging and access controls (with proper deployment)

See [docs/docker-security-best-practices.md](docs/docker-security-best-practices.md) for detailed security hardening guidance.

## Hall of Fame

We appreciate security researchers who responsibly disclose vulnerabilities:

- (No public vulnerabilities reported yet)

Thank you for helping keep MrWhoOidc and our users safe!

---

**Last Updated**: November 2, 2025  
**Version**: 1.0.0
