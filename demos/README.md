# MrWhoOidc Demo Applications

This folder contains the public integration demos for MrWhoOidc.

## Start Here

Do not begin with the demos if the issuer is not already running.

The recommended order is:

1. Complete the base deployment path from [../docs/deployment-paths.md](../docs/deployment-paths.md).
2. Bootstrap and verify the issuer.
3. Return here and choose the demo that matches your stack and flow.

If you need Redis-backed distributed features before you test demos, use the Redis path in [../docs/deployment-paths.md](../docs/deployment-paths.md) and keep following the published-image workflow in this repository.

## Available Demos

| Demo | Stack | Scenario |
|---|---|---|
| [dotnet-mvc-client](./dotnet-mvc-client/) | ASP.NET Core Razor Pages | confidential client with interactive sign-in and downstream API call |
| [react-client](./react-client/) | React + Vite + TypeScript | public SPA client using PKCE and PAR when available |
| [go-client](./go-client/) | Go | confidential web client |
| [kotlin-spring-client](./kotlin-spring-client/) | Kotlin + Spring Boot | Java/Spring confidential client with OBO and M2M patterns |
| [obo-demo-api](./obo-demo-api/) | ASP.NET Core minimal API | delegated token validation and OBO vs M2M comparison |

## Recommended Starting Points

- Start with [dotnet-mvc-client](./dotnet-mvc-client/) if you want the clearest end-to-end .NET example.
- Start with [react-client](./react-client/) if you need a browser-only SPA reference.
- Start with [obo-demo-api](./obo-demo-api/) if you are validating access tokens on a downstream API.

## Choose A Demo By Goal

| Goal | Recommended Demo | Why |
|---|---|---|
| Confidential web app | [dotnet-mvc-client](./dotnet-mvc-client/) | Fastest way to understand the full sign-in and downstream API flow |
| Browser-only SPA | [react-client](./react-client/) | Best starting point for PKCE and PAR in a frontend-only client |
| Downstream API validation | [obo-demo-api](./obo-demo-api/) | Clearest path for access token validation and OBO vs M2M comparison |
| Non-.NET confidential client | [go-client](./go-client/) or [kotlin-spring-client](./kotlin-spring-client/) | Better fit when your application stack is not .NET |

## Local Workflow

The docs in this repo assume you bring up the issuer separately using the root-level deployment assets:

```bash
./scripts/generate-cert.sh localhost changeit
cp .env.example .env
docker compose up -d
```

Once the issuer is running, follow the README inside the specific demo directory.

#### Access Token (OAuth 2.0)

- **Purpose**: Grants access to protected resources (APIs)
- **Format**: Opaque string or JWT
- **Contains**: Scopes, audience, expiration
- **Validation**: Sent to resource server for validation
- **Use Case**: Call downstream APIs

#### Refresh Token (OAuth 2.0)

- **Purpose**: Obtain new access tokens without re-authentication
- **Format**: Opaque string
- **Lifetime**: Long-lived (days to months)
- **Security**: Must be stored securely, rotation recommended
- **Use Case**: Maintain session without frequent logins

### 3. Session Management

#### Server-Side Sessions (.NET MVC, Go)

- **Storage**: Server memory, Redis, or database
- **Cookie**: Encrypted session ID cookie
- **Advantages**: Tokens never exposed to client, revocable sessions
- **Disadvantages**: Server state, horizontal scaling complexity

#### Client-Side Storage (React SPA)

- **Storage**: Browser session storage or local storage
- **Tokens**: Stored directly in browser
- **Advantages**: Stateless, easy horizontal scaling
- **Disadvantages**: Tokens visible in dev tools, cannot revoke without backend

## Client Registration

Before running any demo, register the client in **MrWhoOidc Admin UI**:

1. Navigate to <https://localhost:8443/admin/clients>
2. Login with the admin credentials you created during bootstrap
3. Go to **Clients** → **Create Client**
4. Fill in the form based on demo requirements (see each README)
5. Save and copy the **client secret** (confidential clients only)
6. Update demo configuration with client secret

### Example Client Registration

| Field | .NET MVC | React SPA | Go Client |
|-------|---------|-----------|-----------|
| **Client ID** | `dotnet-mvc-demo` | `react-spa-demo` | `go-demo` |
| **Client Type** | Confidential | Public | Confidential |
| **Grant Types** | `authorization_code`, `refresh_token` | `authorization_code` | `authorization_code`, `refresh_token` |
| **Redirect URIs** | `https://localhost:5001/signin-oidc` | `https://localhost:5173/callback` | `https://localhost:5080/callback` |
| **Post Logout URIs** | `https://localhost:5001/signout-callback-oidc` | `https://localhost:5173/` | `https://localhost:5080/` |
| **Require PKCE** | Optional | **Required** | Optional |
| **Client Secret** | ✅ Generated | ❌ None | ✅ Generated |

## General Integration Guidance

### Choosing the Right Demo

| Scenario | Recommended Demo |
|----------|------------------|
| Building ASP.NET Core web app | .NET MVC Client |
| Building React/Vue/Angular SPA | React SPA Client |
| Building Go microservice | Go Web Client |
| Need server-side rendering | .NET MVC or Go Client |
| Need stateless client | React SPA Client |
| High performance requirements | Go Web Client |
| Enterprise .NET environment | .NET MVC Client |
| Cloud-native architecture | Go or React Client |

### Security Best Practices

1. **Always use HTTPS** in production (self-signed certs OK for development)
2. **Use PKCE** for all clients (mandatory for public clients)
3. **Validate redirect URIs** strictly (no wildcards)
4. **Use state parameter** to prevent CSRF
5. **Use nonce parameter** to prevent replay attacks
6. **Validate ID token signature** using JWKS endpoint
7. **Check token expiration** before using tokens
8. **Rotate client secrets** regularly (confidential clients)
9. **Use short token lifetimes** (1 hour or less)
10. **Store tokens securely** (encrypted, never in logs)

### Common Issues Across All Demos

#### SSL Certificate Errors

**Cause**: MrWhoOidc uses self-signed certificate for development.

**Solution**:

- Trust certificate: `dotnet dev-certs https --trust`
- Or proceed past browser warning for development

#### "Connection Refused" Errors

**Cause**: MrWhoOidc container not running.

**Solution**:

```bash
# Check status
docker ps | grep mrwho-oidc

# Start MrWhoOidc from the deployment repository root
cd /path/to/MrWho
docker compose up -d
```

#### "Invalid Redirect URI" Errors

**Cause**: Redirect URI mismatch between client registration and configuration.

**Solution**:

- Verify redirect URI in Admin UI matches demo configuration exactly
- Check protocol (http vs https), hostname, and port
- No trailing slashes unless specified

#### "Unauthorized Client" Errors

**Cause**: Client not registered or misconfigured.

**Solution**:

- Verify client exists in Admin UI
- Check client ID matches exactly (case-sensitive)
- For confidential clients, verify client secret
- Check grant types include `authorization_code`

## Docker Compose Architecture

All demos extend the parent `docker-compose.yml` using Docker Compose overlay pattern:

```bash
# Parent: MrWho/docker-compose.yml
# - Defines MrWhoOidc services (webauth, postgres, redis)
# - Creates shared networks (mrwho_edge, internal)

# Overlay: demos/<demo>/docker-compose.demo.yml
# - Extends parent configuration
# - Adds demo-specific service
# - Connects to shared networks
# - Sets environment variables
```

**Benefits**:

- **Isolation**: Each demo is independent
- **Orchestration**: Demos wait for MrWhoOidc to be healthy
- **Networking**: Inter-service communication via edge network
- **Reusability**: Single MrWhoOidc instance for all demos

**Running Multiple Demos**:

```bash
# Start MrWhoOidc once
cd MrWho
docker compose up -d

# Start .NET demo
cd demos/dotnet-mvc-client
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d

# Start React demo (in another terminal)
cd demos/react-client
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d

# Start Go demo (in another terminal)
cd demos/go-client
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d
```

All three demos can run simultaneously on different ports.

## Next Steps

### For Developers

1. **Choose a demo** matching your technology stack
2. **Follow the README** for step-by-step instructions
3. **Experiment** with different configurations
4. **Read the code** to understand implementation patterns
5. **Adapt** the demo for your own project

### For Production

1. **Review security best practices** in main documentation
2. **Use proper SSL certificates** (not self-signed)
3. **Configure production OIDC provider** (not localhost)
4. **Enable refresh token rotation** for public clients
5. **Implement proper session management** (Redis, database)
6. **Set up logging and monitoring** (OpenTelemetry)
7. **Review deployment guide**: [docs/deployment-guide.md](../docs/deployment-guide.md)

## Resources

- **MrWhoOidc Documentation**: [docs/README.md](../docs/README.md)
- **Admin Guide**: [docs/admin-guide.md](../docs/admin-guide.md)
- **Developer Guide**: [docs/developer-guide.md](../docs/developer-guide.md)
- **Deployment Guide**: [docs/deployment-guide.md](../docs/deployment-guide.md)
- **Configuration Reference**: [docs/configuration-reference.md](../docs/configuration-reference.md)
- **Troubleshooting**: [docs/troubleshooting.md](../docs/troubleshooting.md)

## Support

- **Issues**: <https://github.com/yourusername/MrWhoOidc/issues>
- **Discussions**: <https://github.com/yourusername/MrWhoOidc/discussions>
- **Documentation**: <https://github.com/yourusername/MrWhoOidc/tree/main/MrWho/docs>

---

**Happy coding! 🚀**

If you have questions or encounter issues, please open an issue on GitHub or start a discussion.
