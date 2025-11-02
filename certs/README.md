# TLS Certificates

This directory stores TLS certificates for HTTPS support.

## Quick Start

Generate a self-signed certificate for development:

```bash
# Linux/macOS/WSL
./scripts/generate-cert.sh localhost changeit

# Windows PowerShell (requires openssl)
bash scripts/generate-cert.sh localhost changeit
```

This creates `aspnetapp.pfx` with password `changeit`.

## What Gets Created

After running the script:

```
certs/
├── aspnetapp.pfx    # Certificate for Docker (gitignored)
├── aspnetapp.pem    # PEM format (gitignored)
└── README.md        # This file (tracked in git)
```

## Production Certificates

**⚠️ Self-signed certificates are for development only.**

For production, use a CA-signed certificate:

### Option 1: Let's Encrypt (Free, Automated)

```bash
# Install certbot
sudo apt-get install certbot  # Ubuntu/Debian
brew install certbot          # macOS

# Generate certificate
sudo certbot certonly --standalone -d auth.example.com

# Convert to PFX
sudo openssl pkcs12 -export \
  -out certs/production.pfx \
  -inkey /etc/letsencrypt/live/auth.example.com/privkey.pem \
  -in /etc/letsencrypt/live/auth.example.com/cert.pem \
  -certfile /etc/letsencrypt/live/auth.example.com/chain.pem \
  -passout pass:YourStrongPassword

# Update .env
CERT_PASSWORD=YourStrongPassword
```

### Option 2: Commercial CA (Namecheap, DigiCert, etc.)

```bash
# 1. Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout certs/server.key \
  -out certs/server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=auth.example.com"

# 2. Submit CSR to CA and receive certificate files

# 3. Convert to PFX
openssl pkcs12 -export \
  -out certs/production.pfx \
  -inkey certs/server.key \
  -in certs/server.crt \
  -certfile certs/ca-bundle.crt \
  -passout pass:YourStrongPassword

# 4. Update docker-compose.yml volumes section
volumes:
  - ./certs/production.pfx:/https/aspnetapp.pfx:ro

# 5. Update .env
CERT_PASSWORD=YourStrongPassword
```

## Certificate Requirements

- **Format**: PKCS#12 (.pfx) with private key
- **Password**: Set in `CERT_PASSWORD` environment variable
- **Algorithm**: RSA 2048-bit minimum (4096-bit recommended)
- **Validity**: Valid dates (not expired, not not-yet-valid)
- **Common Name (CN)**: Must match `OIDC_PUBLIC_BASE_URL` domain

## Security Notes

- **Never commit certificates to git** - they are gitignored by default
- **Use strong passwords** for production certificates (16+ characters)
- **Rotate certificates before expiration** (90 days for Let's Encrypt, 1 year for commercial)
- **Restrict file permissions**: `chmod 600 certs/*.pfx` on Linux/macOS
- **Store production certificates securely** - consider using secrets management (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault)

## Troubleshooting

### "Certificate file not found"

**Symptom**: Container fails to start with certificate error

**Solution**:

```bash
# Verify certificate exists
ls -la certs/aspnetapp.pfx

# If missing, regenerate
./scripts/generate-cert.sh localhost changeit
```

### "Password authentication failed"

**Symptom**: Container starts but HTTPS fails

**Solution**:

```bash
# Verify password matches
cat .env | grep CERT_PASSWORD

# Should match password used in generate-cert.sh
# Regenerate with correct password if needed
./scripts/generate-cert.sh localhost your-actual-password
```

### "The SSL connection could not be established"

**Symptom**: Browser shows certificate error

**Solution**:

```bash
# For development with self-signed certificates:
# - Accept browser security warning, or
# - Trust certificate in OS keychain (see deployment guide)

# For production:
# - Use CA-signed certificate from Let's Encrypt or commercial CA
```

### Certificate expires soon

**Solution**:

```bash
# Check expiration
openssl pkcs12 -in certs/aspnetapp.pfx -nokeys -passin pass:changeit | openssl x509 -noout -enddate

# Renew Let's Encrypt certificate
sudo certbot renew

# Convert renewed certificate to PFX
# (See Let's Encrypt section above)
```

## See Also

- [Deployment Guide](../docs/deployment-guide.md) - TLS configuration in production
- [Docker Security Best Practices](../docs/docker-security-best-practices.md) - Certificate management
- [Troubleshooting Guide](../docs/troubleshooting.md) - Certificate issues
