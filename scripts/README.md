# MrWhoOidc Scripts

Utility scripts for certificate generation and deployment verification.

## Scripts

### generate-cert.sh

Generates self-signed TLS certificates for development and testing.

**Usage:**

```bash
./scripts/generate-cert.sh [domain] [password]
```

**Arguments:**

- `domain` - Domain name for the certificate (default: `localhost`)
- `password` - Certificate password for PFX file (default: `changeit`)

**Example:**

```bash
# Generate certificate for localhost
./scripts/generate-cert.sh

# Generate certificate for custom domain
./scripts/generate-cert.sh myapp.local mypassword123
```

**Output:**

- `certs/aspnetapp.pfx` - PFX certificate file ready for ASP.NET Core
- Certificate valid for 365 days
- Includes Subject Alternative Names (SANs) for domain, wildcard, and 127.0.0.1

**Requirements:**

- OpenSSL installed and available in PATH
- Write permissions to `certs/` directory

**Important Notes:**

- ⚠️ **Self-signed certificates are for DEVELOPMENT ONLY**
- For production, use certificates from a trusted Certificate Authority
- Update `.env` file with certificate password: `CERT_PASSWORD=yourpassword`
- Browsers will show security warnings for self-signed certificates

**Trusting the Certificate (Optional for Development):**

macOS:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/aspnetapp.pfx
```

Windows:

```powershell
# Import to Trusted Root Certification Authorities store via certmgr.msc
```

Linux:

```bash
# Extract CRT from PFX first, then:
sudo cp certs/aspnetapp.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### health-check.sh

Validates that MrWhoOidc deployment is healthy and operational.

**Usage:**

```bash
./scripts/health-check.sh [base-url]
```

**Arguments:**

- `base-url` - Base URL of MrWhoOidc instance (default: `http://localhost:8080`)

**Example:**

```bash
# Check default local deployment
./scripts/health-check.sh

# Check custom deployment
./scripts/health-check.sh https://auth.example.com
```

**Health Checks Performed:**

1. **OpenID Discovery Endpoint** - Validates `/.well-known/openid-configuration` responds with valid JSON containing required OIDC metadata
2. **JWKS Endpoint** - Validates `/jwks` returns valid JSON Web Key Set with at least one signing key
3. **Health Endpoint** - Validates `/health` returns HTTP 200 status
4. **Admin UI** - Validates `/admin` is accessible (HTTP 200 or 302 redirect to login)
5. **Docker Containers** - Validates all expected containers are running (mrwho-oidc, mrwho-postgres, optionally mrwho-redis)

**Exit Codes:**

- `0` - All health checks passed
- `1` - One or more health checks failed

**Output:**

Colored output with check marks (✓) for passed checks and crosses (✗) for failed checks. Failed checks include troubleshooting guidance.

**Requirements:**

- `curl` installed and available in PATH
- `jq` installed for JSON validation
- `docker` installed for container checks
- Network access to MrWhoOidc deployment

**Troubleshooting:**

If health checks fail, the script provides specific troubleshooting steps:

- Container not running → Check `docker-compose logs`
- Network errors → Verify base URL and firewall rules
- Invalid JSON responses → Check application logs for errors
- Missing JWKS keys → Verify key generation completed during initialization

## Common Workflows

### Initial Setup

```bash
# 1. Generate TLS certificate
./scripts/generate-cert.sh localhost changeit

# 2. Update .env with certificate password
echo "CERT_PASSWORD=changeit" >> .env

# 3. Start containers
docker compose up -d

# 4. Wait for initialization (30-60 seconds)
sleep 60

# 5. Verify deployment
./scripts/health-check.sh
```

### Production Deployment

```bash
# 1. Obtain production certificate from trusted CA
# 2. Place certificate in certs/aspnetapp.pfx
# 3. Update .env with production settings
# 4. Start containers
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 5. Verify deployment
./scripts/health-check.sh https://auth.example.com
```

### Development with Custom Domain

```bash
# 1. Add custom domain to /etc/hosts
echo "127.0.0.1 myapp.local" | sudo tee -a /etc/hosts

# 2. Generate certificate for custom domain
./scripts/generate-cert.sh myapp.local changeit

# 3. Update .env with custom domain
echo "OIDC_ISSUER=https://myapp.local:8443" >> .env

# 4. Start containers
docker compose up -d

# 5. Verify deployment
./scripts/health-check.sh https://myapp.local:8443
```

## Script Requirements

Both scripts require:

- Bash shell (Linux, macOS, Git Bash on Windows, WSL)
- Execute permissions: `chmod +x scripts/*.sh`

Platform-specific notes:

- **Windows**: Use Git Bash, WSL, or PowerShell with bash compatibility
- **macOS**: Scripts work out of the box
- **Linux**: Scripts work out of the box

## Support

For issues or questions:

- Check main [README.md](../README.md) for general documentation
- Review [Quick Start Guide](../docs/quick-start.md) for deployment instructions
- Review logs: `docker-compose logs mrwho-oidc`
- File issues on GitHub repository
