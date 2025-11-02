# MrWhoOidc Troubleshooting Guide

**Version**: 1.0.0  
**Last Updated**: November 2, 2025  
**Target Audience**: Operations engineers, DevOps teams, Developers

Comprehensive troubleshooting guide for common issues and their solutions.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Deployment Issues](#deployment-issues)
3. [Certificate and TLS Issues](#certificate-and-tls-issues)
4. [Database Issues](#database-issues)
5. [Redis Issues](#redis-issues)
6. [Email Issues](#email-issues)
7. [Authentication Issues](#authentication-issues)
8. [Performance Issues](#performance-issues)
9. [Docker Issues](#docker-issues)
10. [Diagnostic Commands Reference](#diagnostic-commands-reference)

## Quick Diagnostics

Before diving into specific issues, run these quick checks:

```bash
# 1. Check all services are running
docker compose ps

# 2. Check service logs
docker compose logs --tail=50 mrwho-oidc

# 3. Run health check
./scripts/health-check.sh

# 4. Verify network connectivity
docker compose exec mrwho-oidc curl -k https://localhost:8443/health

# 5. Check disk space
df -h

# 6. Check Docker resources
docker stats --no-stream
```

## Deployment Issues

### Issue 1: Port Conflict - "Address already in use"

**Symptoms**:
- Error: `bind: address already in use`
- Container fails to start
- Port 8443 or 8081 already in use

**Cause**: Another service is using ports 8443 or 8081.

**Solution**:

```bash
# Check what's using the ports
# Linux/macOS
sudo lsof -i :8443
sudo lsof -i :8081

# Windows
netstat -ano | findstr :8443
netstat -ano | findstr :8081

# Option 1: Stop conflicting service
# Option 2: Change MrWhoOidc ports in .env
echo "OIDC_HTTPS_PORT=9443" >> .env
echo "OIDC_HTTP_PORT=9081" >> .env

# Restart services
docker compose down
docker compose up -d
```

### Issue 2: Missing Required Environment Variables

**Symptoms**:
- Warning: `The 'POSTGRES_PASSWORD' variable is not set`
- Container starts but fails immediately
- Error logs show missing configuration

**Cause**: `.env` file missing or incomplete.

**Solution**:

```bash
# Copy template if missing
cp .env.example .env

# Verify required variables are set
cat .env | grep -E "POSTGRES_PASSWORD|CERT_PASSWORD|OIDC_PUBLIC_BASE_URL"

# Edit .env and set all REQUIRED variables
nano .env

# Required minimum:
# POSTGRES_PASSWORD=YourSecurePassword123!
# CERT_PASSWORD=changeit
# OIDC_PUBLIC_BASE_URL=https://localhost:8443

# Restart services
docker compose down
docker compose up -d
```

### Issue 3: Container Exits Immediately After Starting

**Symptoms**:
- Container status shows "Exited (1)"
- `docker compose ps` shows container not running
- Services don't stay up

**Cause**: Configuration error, missing dependencies, or startup failure.

**Solution**:

```bash
# Check exit code and last logs
docker compose ps
docker compose logs mrwho-oidc | tail -100

# Common causes and fixes:

# 1. Database not ready
# Wait for postgres health check
docker compose up -d mrwho-postgres
sleep 30
docker compose up -d mrwho-oidc

# 2. Invalid configuration
# Validate docker-compose.yml
docker compose config

# 3. Certificate not found
ls -la certs/aspnetapp.pfx
# If missing, regenerate:
./scripts/generate-cert.sh localhost changeit

# 4. Permission issues
chmod 644 certs/aspnetapp.pfx
chmod 755 scripts/*.sh
```

## Certificate and TLS Issues

### Issue 4: Certificate Errors - "The SSL connection could not be established"

**Symptoms**:
- Error: `The SSL connection could not be established`
- Browser shows certificate error
- Clients cannot connect over HTTPS

**Cause**: Missing, expired, or incorrectly configured TLS certificate.

**Solution**:

```bash
# 1. Verify certificate exists
ls -la certs/aspnetapp.pfx
# Should show file with size >1KB

# 2. Check certificate is mounted
docker compose config | grep -A5 volumes

# 3. Regenerate certificate
./scripts/generate-cert.sh localhost changeit

# 4. Verify CERT_PASSWORD matches
cat .env | grep CERT_PASSWORD
# Should be: CERT_PASSWORD=changeit (or your chosen password)

# 5. Ensure certificate is mounted in docker-compose.yml
# Should have:
# volumes:
#   - ./certs:/https:ro

# 6. Restart services
docker compose restart mrwho-oidc

# 7. Test certificate
openssl s_client -connect localhost:8443 -showcerts
```

### Issue 5: Browser Shows "Your Connection is Not Private"

**Symptoms**:
- Browser warning about untrusted certificate
- NET::ERR_CERT_AUTHORITY_INVALID
- Users cannot bypass warning easily

**Cause**: Self-signed certificate not trusted by browser.

**Solution**:

**Option 1: Trust Certificate (Development Only)**

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/aspnetapp.pfx

# Windows
# 1. Double-click certs/aspnetapp.pfx
# 2. Import to "Trusted Root Certification Authorities"

# Linux
# Extract CRT from PFX first:
openssl pkcs12 -in certs/aspnetapp.pfx -clcerts -nokeys -out certs/aspnetapp.crt
sudo cp certs/aspnetapp.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Option 2: Use Production Certificate**

```bash
# Obtain certificate from Let's Encrypt
sudo certbot certonly --standalone -d auth.example.com

# Convert to PFX
sudo openssl pkcs12 -export \
  -out certs/production.pfx \
  -inkey /etc/letsencrypt/live/auth.example.com/privkey.pem \
  -in /etc/letsencrypt/live/auth.example.com/cert.pem \
  -certfile /etc/letsencrypt/live/auth.example.com/chain.pem

# Update .env
echo "CERT_PASSWORD=your_password" >> .env

# Restart
docker compose restart mrwho-oidc
```

## Database Issues

### Issue 6: Database Connection Failed

**Symptoms**:
- Error: `Connection refused` or `Connection timeout`
- Error: `password authentication failed`
- Application cannot connect to PostgreSQL

**Cause**: PostgreSQL not ready, incorrect credentials, or network issue.

**Solution**:

```bash
# 1. Check PostgreSQL health
docker compose ps mrwho-postgres
# Status should be "healthy"

# 2. If not healthy, check PostgreSQL logs
docker compose logs mrwho-postgres | tail -50

# 3. Verify POSTGRES_PASSWORD in .env
cat .env | grep POSTGRES_PASSWORD

# 4. Wait for PostgreSQL initialization (30-60 seconds)
docker compose logs -f mrwho-postgres
# Look for: "database system is ready to accept connections"

# 5. Test connection manually
docker compose exec mrwho-postgres psql -U oidc -d authdb -c "SELECT 1;"
# Should output: 1

# 6. If password wrong, reset:
docker compose down -v  # WARNING: Destroys all data
# Update .env with correct POSTGRES_PASSWORD
docker compose up -d
```

### Issue 7: Database Migrations Failed

**Symptoms**:
- Error: `Migration failed`
- Error: `Table already exists` or `Column not found`
- Application starts but database schema incorrect

**Cause**: Database schema not initialized, interrupted migration, or version mismatch.

**Solution**:

```bash
# 1. View application logs for specific error
docker compose logs mrwho-oidc | grep -i migration

# 2. Check current database state
docker compose exec mrwho-postgres psql -U oidc -d authdb -c "\dt"
# Lists all tables

# 3. For clean environment, reset database
# WARNING: This destroys all data
docker compose down
docker volume rm mrwho_postgres-data
docker compose up -d

# 4. Watch migration progress
docker compose logs -f mrwho-oidc | grep -i migration

# 5. For production upgrades, see docs/upgrade-guide.md
```

## Redis Issues

### Issue 8: Redis Connection Failed

**Symptoms**:
- Warning: `Redis connection failed`
- Application starts but Redis features disabled
- Performance not improved despite Redis enabled

**Cause**: Redis not running, incorrect connection string, or network issue.

**Solution**:

```bash
# 1. Verify Redis is running
docker compose ps mrwho-redis
# Should show "running" and "healthy"

# 2. Check Redis logs
docker compose logs mrwho-redis | tail -20

# 3. Test Redis connection
docker compose exec mrwho-redis redis-cli ping
# Should output: PONG

# 4. Verify Redis configuration in .env
cat .env | grep REDIS
# REDIS_ENABLED should be true
# REDIS_CONNECTION_STRING should be correct

# 5. Ensure using docker-compose.redis.yml
docker compose -f docker-compose.yml -f docker-compose.redis.yml config | grep redis

# 6. Restart Redis
docker compose restart mrwho-redis
```

### Issue 9: Redis Memory Issues

**Symptoms**:
- Redis logs show: `OOM command not allowed`
- Keys being evicted unexpectedly
- Performance degradation

**Cause**: Redis memory limit exceeded.

**Solution**:

```bash
# 1. Check Redis memory usage
docker compose exec mrwho-redis redis-cli INFO memory | grep used_memory_human

# 2. Check Redis maxmemory setting
docker compose exec mrwho-redis redis-cli CONFIG GET maxmemory
# Should show limit (e.g., 536870912 = 512MB)

# 3. Increase maxmemory in docker-compose.redis.yml
# Edit: --maxmemory 1gb (increase as needed)

# 4. Apply changes
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d --force-recreate mrwho-redis

# 5. Clear cache if needed
docker compose exec mrwho-redis redis-cli FLUSHDB
```

## Email Issues

### Issue 10: Emails Not Being Sent

**Symptoms**:
- Password reset emails not received
- Verification emails not sent
- No SMTP errors in logs

**Cause**: Email disabled, incorrect SMTP configuration, or firewall blocking.

**Solution**:

```bash
# 1. Verify email enabled
cat .env | grep MAIL_ENABLED
# Should be: MAIL_ENABLED=true

# 2. Check SMTP configuration
cat .env | grep MAIL_

# 3. View application logs for SMTP errors
docker compose logs mrwho-oidc | grep -i mail

# 4. Test SMTP connection
docker compose exec mrwho-oidc bash -c "telnet $MAIL_SMTP_HOST $MAIL_SMTP_PORT"
# Should connect successfully

# 5. For development, use MailHog
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
# Access MailHog UI: http://localhost:8025

# 6. Check spam folder
# Verify MAIL_FROM_ADDRESS has valid SPF/DKIM records
```

## Authentication Issues

### Issue 11: "Issuer Mismatch" Error in Client Applications

**Symptoms**:
- Client apps fail with "issuer mismatch"
- Tokens rejected as invalid
- Authentication flow breaks

**Cause**: `OIDC_PUBLIC_BASE_URL` doesn't match actual URL used by clients.

**Solution**:

```bash
# 1. Check current configuration
cat .env | grep OIDC_PUBLIC_BASE_URL

# 2. Verify discovery endpoint issuer
curl -k https://localhost:8443/.well-known/openid-configuration | jq .issuer

# 3. Ensure URLs match exactly (protocol, domain, port)
# If accessing via https://localhost:8443
# Then OIDC_PUBLIC_BASE_URL=https://localhost:8443

# If accessing via https://auth.example.com
# Then OIDC_PUBLIC_BASE_URL=https://auth.example.com

# 4. Update .env with correct URL
echo "OIDC_PUBLIC_BASE_URL=https://your-actual-url" >> .env

# 5. Restart application
docker compose restart mrwho-oidc

# 6. Verify fix
curl -k https://your-actual-url/.well-known/openid-configuration | jq .issuer
```

### Issue 12: Admin UI Login Fails

**Symptoms**:
- Cannot login to `/admin`
- "Invalid credentials" error
- Default password doesn't work

**Cause**: Default admin password changed or database issue.

**Solution**:

```bash
# 1. Try default credentials
# Username: admin
# Password: Admin123!

# 2. If fails, check application logs
docker compose logs mrwho-oidc | grep -i "login\|authentication"

# 3. Reset admin password via database
docker compose exec mrwho-postgres psql -U oidc -d authdb
# Run SQL to reset password (see admin-guide.md)

# 4. Verify admin UI is enabled
cat .env | grep ADMIN_UI_ENABLED
# Should be: ADMIN_UI_ENABLED=true

# 5. Clear browser cache and cookies

# 6. Try incognito/private browsing mode
```

## Performance Issues

### Issue 13: Slow Response Times

**Symptoms**:
- Requests take >1 second
- Token validation slow
- Discovery endpoint slow

**Cause**: No caching, database slow, or resource constraints.

**Solution**:

```bash
# 1. Enable Redis caching (30-50% faster)
echo "REDIS_ENABLED=true" >> .env
docker compose -f docker-compose.yml -f docker-compose.redis.yml up -d

# 2. Check resource usage
docker stats mrwho-oidc mrwho-postgres
# Look for high CPU or memory usage

# 3. Check database query performance
docker compose exec mrwho-postgres psql -U oidc -d authdb
# Run: EXPLAIN ANALYZE SELECT * FROM clients LIMIT 10;

# 4. Increase resource limits
# Edit docker-compose.production.yml deploy.resources sections

# 5. Check disk I/O
docker stats --no-stream

# 6. Review logs for slow queries
docker compose logs mrwho-oidc | grep -i "slow\|timeout"
```

## Docker Issues

### Issue 14: "No Space Left on Device"

**Symptoms**:
- Error: `no space left on device`
- Containers fail to start
- Cannot create files

**Cause**: Disk full, Docker images/volumes consuming too much space.

**Solution**:

```bash
# 1. Check disk space
df -h

# 2. Check Docker disk usage
docker system df

# 3. Clean up unused Docker resources
docker system prune -a --volumes
# WARNING: Removes unused images, containers, volumes

# 4. Remove specific unused volumes
docker volume ls
docker volume rm volume_name

# 5. Check application logs size
du -sh /var/lib/docker/containers/*

# 6. Configure log rotation in docker-compose.yml
# Add to each service:
# logging:
#   driver: "json-file"
#   options:
#     max-size: "10m"
#     max-file: "3"
```

### Issue 15: Image Pull Failures

**Symptoms**:
- Error: `failed to pull image`
- Error: `unauthorized` or `not found`
- Cannot download mrwhooidc image

**Cause**: Network issue, rate limiting, or image not available.

**Solution**:

```bash
# 1. Check network connectivity
ping ghcr.io

# 2. Verify image exists
# Visit: https://github.com/popicka70/mrwhooidc/pkgs/container/mrwhooidc

# 3. Pull image manually
docker pull ghcr.io/popicka70/mrwhooidc:latest

# 4. If rate limited, wait and retry
# GitHub Container Registry has rate limits

# 5. Use specific version instead of latest
# In docker-compose.yml:
# image: ghcr.io/popicka70/mrwhooidc:v1.0.0

# 6. Check Docker daemon configuration
docker info | grep -i registry
```

## Diagnostic Commands Reference

### Service Status

```bash
# List all services
docker compose ps

# Check specific service
docker compose ps mrwho-oidc

# View service logs (last 100 lines)
docker compose logs --tail=100 mrwho-oidc

# Follow logs in real-time
docker compose logs -f mrwho-oidc

# View logs for specific time period
docker compose logs --since 10m mrwho-oidc
```

### Health Checks

```bash
# Run included health check script
./scripts/health-check.sh

# Manual health checks
curl -k https://localhost:8443/health
curl -k https://localhost:8443/.well-known/openid-configuration
curl -k https://localhost:8443/jwks

# Check from inside container
docker compose exec mrwho-oidc curl -k https://localhost:8443/health
```

### Database Diagnostics

```bash
# Connect to PostgreSQL
docker compose exec mrwho-postgres psql -U oidc -d authdb

# List tables
docker compose exec mrwho-postgres psql -U oidc -d authdb -c "\dt"

# Check table sizes
docker compose exec mrwho-postgres psql -U oidc -d authdb -c "\dt+"

# Run query
docker compose exec mrwho-postgres psql -U oidc -d authdb -c "SELECT COUNT(*) FROM clients;"
```

### Redis Diagnostics

```bash
# Check Redis connection
docker compose exec mrwho-redis redis-cli ping

# View Redis info
docker compose exec mrwho-redis redis-cli INFO

# Check keys
docker compose exec mrwho-redis redis-cli KEYS "mrwho:*"

# Monitor Redis commands
docker compose exec mrwho-redis redis-cli MONITOR
```

### Network Diagnostics

```bash
# Test connectivity from mrwho-oidc to postgres
docker compose exec mrwho-oidc ping mrwho-postgres

# Check exposed ports
docker compose port mrwho-oidc 8443

# Inspect network
docker network inspect mrwho_internal
```

### Resource Monitoring

```bash
# View resource usage
docker stats

# View resource usage snapshot
docker stats --no-stream

# Check specific container
docker stats mrwho-oidc
```

## Getting Help

If issues persist after trying these solutions:

1. **Check Logs**: `docker compose logs -f mrwho-oidc` for detailed error messages
2. **Review Configuration**: Verify all required environment variables are set
3. **Consult Documentation**: See `/docs` directory for detailed guides
4. **Community Support**: [File an issue on GitHub](https://github.com/popicka70/mrwhooidc/issues)
5. **Security Issues**: See [SECURITY.md](../SECURITY.md) for private vulnerability reporting

## See Also

- [Deployment Guide](deployment-guide.md) - Deployment instructions
- [Configuration Reference](configuration-reference.md) - All configuration options
- [Upgrade Guide](upgrade-guide.md) - Version upgrades
- [Docker Security Best Practices](docker-security-best-practices.md) - Security hardening
