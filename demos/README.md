# MrWhoOidc Demo Applications

This directory contains three complete demo applications showcasing different integration patterns with **MrWhoOidc** as an OpenID Connect (OIDC) Provider. Each demo demonstrates a real-world client implementation using best practices for authentication and authorization.

## Available Demos

| Demo | Technology | Client Type | Use Case | Documentation |
|------|-----------|-------------|----------|---------------|
| **[.NET MVC Client](./dotnet-mvc-client/)** | ASP.NET Core 9, Razor Pages | Confidential | Traditional server-rendered web applications | [README](./dotnet-mvc-client/README.md) |
| **[Kotlin Spring Client](./kotlin-spring-client/)** | Kotlin, Spring Boot | Confidential | Non-.NET server-rendered web apps + OBO/M2M | [README](./kotlin-spring-client/README.md) |
| **[React SPA Client](./react-client/)** | React 18, Vite, TypeScript | Public | Single-page applications (SPAs), browser-based authentication | [README](./react-client/README.md) |
| **[Go Web Client](./go-client/)** | Go 1.21+, net/http | Confidential | Native Go web applications, microservices | [README](./go-client/README.md) |

## Quick Start

All demos support **Docker Compose** for rapid deployment alongside MrWhoOidc. Each demo includes:

- ✅ Complete working code
- ✅ Docker Compose integration
- ✅ Comprehensive documentation
- ✅ Configuration examples
- ✅ Troubleshooting guides

### Prerequisites

- **Docker Desktop** or **Docker Engine** with Docker Compose V2
- **Git**
- **Web Browser** (Chrome, Firefox, Edge, Safari)

### Running a Demo

Each demo follows a consistent pattern:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/MrWhoOidc.git
   cd MrWhoOidc/MrWho/demos
   ```

2. **Choose a demo** (e.g., .NET MVC):

   ```bash
   cd dotnet-mvc-client
   ```

3. **Start the OIDC provider and demo**:

   ```bash
   docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d
   ```

4. **Register the client** in Admin UI at <https://localhost:8443/admin>

5. **Configure client secret** (if confidential client) in `.env` file

6. **Test authentication** by navigating to the demo URL

For detailed instructions, see each demo's README.

## Technology Stack Comparison

### .NET MVC Client

**Best for**: Enterprise web applications, .NET developers, ASP.NET Core projects

- **Framework**: ASP.NET Core 9 with Razor Pages
- **Authentication Library**: Microsoft.AspNetCore.Authentication.OpenIdConnect (built-in)
- **OIDC Flow**: Authorization Code with PKCE
- **Client Type**: Confidential (uses client secret)
- **Session Management**: ASP.NET Core Identity cookies
- **Token Storage**: Server-side encrypted authentication ticket
- **Port**: 5001

**Key Features**:

- Seamless integration with ASP.NET Core middleware
- Built-in CSRF protection
- Server-side session management
- Token refresh support
- Minimal configuration required

**When to Use**:

- Building ASP.NET Core web applications
- Need server-side rendering (SSR)
- Require confidential client security
- Enterprise environments with .NET infrastructure

---

### React SPA Client

**Best for**: Modern single-page applications, JavaScript developers, mobile-like web experiences

- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite (fast HMR, ES modules)
- **Authentication Library**: oauth4webapi (standards-compliant, lightweight)
- **OIDC Flow**: Authorization Code with PKCE (required for public clients)
- **Client Type**: Public (no client secret, browser-based)
- **Session Management**: Browser session/local storage
- **Token Storage**: Browser storage (session or local)
- **Port**: 5173 (dev), 80 (production nginx)

**Key Features**:

- Full browser-based authentication
- PKCE protection against code interception
- No backend required for authentication
- Hot module replacement for development
- Production-ready nginx deployment

**When to Use**:

- Building modern SPAs (React, Vue, Angular)
- Mobile-first web applications
- Microservices architecture (no session state)
- Progressive Web Apps (PWAs)

---

### Go Web Client

**Best for**: Go developers, microservices, cloud-native applications, high-performance backends

- **Framework**: Go 1.21+ with native net/http
- **Authentication Library**: coreos/go-oidc v3
- **OIDC Flow**: Authorization Code with PKCE
- **Client Type**: Confidential (uses client secret)
- **Session Management**: In-memory encrypted sessions (demo) or Redis/database
- **Token Storage**: Server-side session storage
- **Port**: 5080

**Key Features**:

- Minimal dependencies (native Go libraries)
- High performance and low memory footprint
- JSON configuration with environment override
- PKCE support for enhanced security
- Easy integration with Go microservices

**When to Use**:

- Building Go web applications or APIs
- Cloud-native microservices
- Performance-critical applications
- Containerized environments (Kubernetes)
- Want minimal dependencies

## Client Type: Confidential vs Public

### Confidential Clients (.NET MVC, Go)

**Definition**: Clients that can securely store credentials (client secrets).

**Characteristics**:

- Run on trusted servers (backend applications)
- Use client secret for authentication
- Store tokens server-side (not exposed to browser)
- Support refresh tokens with higher security
- Examples: Web applications, backend APIs, microservices

**Security Advantages**:

- Client secret never exposed to end users
- Tokens never sent to browser (except ID token for claims)
- Can use refresh tokens without security risk
- Server-side session validation

### Public Clients (React SPA)

**Definition**: Clients that cannot securely store credentials (e.g., browser-based SPAs, mobile apps).

**Characteristics**:

- Run entirely in browser or on user's device
- **No client secret** (cannot be kept confidential)
- **PKCE required** to protect authorization code
- Tokens stored in browser (session/local storage)
- Examples: SPAs (React, Vue, Angular), mobile apps

**Security Considerations**:

- PKCE (Proof Key for Code Exchange) is **mandatory**
- Tokens visible in browser storage (dev tools)
- Short token lifetimes recommended (1 hour or less)
- Refresh tokens should be used carefully (rotation recommended)
- Cannot authenticate to backend without exposing credentials

## Common Integration Patterns

### 1. Authorization Code Flow with PKCE

All three demos implement **Authorization Code Flow with PKCE**, the current best practice for OIDC authentication:

1. Client generates `code_verifier` (random string) and `code_challenge` (SHA256 hash)
2. Client redirects to `/authorize` with `code_challenge`
3. User authenticates at OIDC provider
4. Provider redirects back with authorization `code`
5. Client exchanges `code` + `code_verifier` for tokens
6. Provider validates `code_verifier` matches original `code_challenge`

**Why PKCE?**

- Protects against authorization code interception
- Required for public clients, recommended for all clients
- Prevents man-in-the-middle attacks
- Standard in OAuth 2.1 specification

### 2. Token Types

#### ID Token (OIDC)

- **Purpose**: Proves user identity
- **Format**: JWT (JSON Web Token)
- **Contains**: User claims (sub, name, email, etc.)
- **Validation**: Signature verification, issuer check, expiry check
- **Use Case**: Display user information

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

1. Navigate to <https://localhost:8443/admin>
2. Login with admin credentials (default: `admin@example.com` / `Admin123!`)
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

# Start MrWhoOidc
cd MrWhoOidc/MrWho
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
