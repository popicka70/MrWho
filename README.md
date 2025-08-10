# MrWho OIDC Service

A complete OpenID Connect (OIDC) authentication service built with ASP.NET Core 9 and OpenIddict. This service provides OAuth 2.0/OIDC endpoints for authentication and authorization.

## 🚀 Features

- **OpenID Connect Server** using OpenIddict 7.0
- **Multiple Grant Types**:
  - Client Credentials Flow
  - Resource Owner Password Credentials Flow  
  - Refresh Token Flow
- **ASP.NET Core Identity** integration for user management
- **SQLite Database** for development and testing
- **Development-ready** with seeded test data

## 🛠️ Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [Visual Studio Code](https://code.visualstudio.com/)
- PowerShell (for running commands)

## 📦 Installation & Setup

### 1. Clone and Navigate to Project
```powershell
Set-Location MrWho
```

### 2. Restore Dependencies
```powershell
dotnet restore
```

### 3. Initialize Database
```powershell
# Create initial migration (if not already done)
dotnet ef migrations add InitialCreate

# Apply migrations to create database
dotnet ef database update
```

### 4. Run the Application
```powershell
dotnet run
```

The application will start and be available at:
- **HTTPS**: `https://localhost:7000`
- **HTTP**: `http://localhost:5000`

## 🧪 Testing the OIDC Service

### Default Test Data

The application automatically seeds the following test data:

#### Test Users
| Username | Password | Email Confirmed |
|----------|----------|-----------------|
| `test@example.com` | `Test123!` | ✅ Yes |
| `admin@example.com` | `Admin123!` | ✅ Yes |

#### Test Client Application
| Property | Value |
|----------|--------|
| **Client ID** | `postman_client` |
| **Client Secret** | `postman_secret` |
| **Grant Types** | Client Credentials, Password, Refresh Token |
| **Scopes** | email, profile, roles |

### OIDC Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/connect/token` | POST | Token endpoint for all grant types |
| `/connect/userinfo` | GET | User information endpoint (requires token) |
| `/` | GET | Service status and information page |

## 🔧 Testing Methods

### Method 1: PowerShell (Recommended)

#### Test Client Credentials Grant
```powershell
$clientCredentialsBody = @{
    grant_type = "client_credentials"
    client_id = "postman_client"
    client_secret = "postman_secret"
    scope = "email profile"
}

$response = Invoke-RestMethod -Uri "https://localhost:7000/connect/token" -Method POST -ContentType "application/x-www-form-urlencoded" -Body $clientCredentialsBody

# Display the token
$response | ConvertTo-Json -Depth 3
```

#### Test Password Grant
```powershell
$passwordGrantBody = @{
    grant_type = "password"
    client_id = "postman_client"
    client_secret = "postman_secret"
    username = "test@example.com"
    password = "Test123!"
    scope = "email profile"
}

$response = Invoke-RestMethod -Uri "https://localhost:7000/connect/token" -Method POST -ContentType "application/x-www-form-urlencoded" -Body $passwordGrantBody

# Display the token
$response | ConvertTo-Json -Depth 3
```

#### Test UserInfo Endpoint
```powershell
# First get a token using password grant (from above)
$token = $response.access_token

# Call UserInfo endpoint
$headers = @{
    Authorization = "Bearer $token"
}

$userInfo = Invoke-RestMethod -Uri "https://localhost:7000/connect/userinfo" -Method GET -Headers $headers
$userInfo | ConvertTo-Json -Depth 3
```

### Method 2: cURL

#### Client Credentials Grant
```bash
curl -X POST https://localhost:7000/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=postman_client&client_secret=postman_secret&scope=email profile"
```

#### Password Grant
```bash
curl -X POST https://localhost:7000/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=postman_client&client_secret=postman_secret&username=test@example.com&password=Test123!&scope=email profile"
```

### Method 3: Postman

1. **Create a new collection** called "MrWho OIDC Tests"

2. **Add Token Endpoint Request**:
   - **Method**: POST
   - **URL**: `https://localhost:7000/connect/token`
   - **Headers**: `Content-Type: application/x-www-form-urlencoded`
   - **Body** (x-www-form-urlencoded):
     ```
     grant_type: client_credentials
     client_id: postman_client
     client_secret: postman_secret
     scope: email profile
     ```

## 📋 Expected Responses

### Successful Token Response
```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "email profile"
}
```

### Successful UserInfo Response
```json
{
    "sub": "12345678-1234-1234-1234-123456789012",
    "email": "test@example.com", 
    "name": "test@example.com",
    "preferred_username": "test@example.com",
    "email_verified": true
}
```

## 🔍 Troubleshooting

### Common Issues

#### Missing Token Endpoint Implementation
If you get 404 errors on `/connect/token`, you need to add the token endpoint to Program.cs:

```csharp
// Add this before app.Run()
app.MapPost("/connect/token", async (HttpContext context) =>
{
    var request = context.GetOpenIddictServerRequest() ??
                  throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    if (request.IsPasswordGrantType())
    {
        var userManager = context.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
        var user = await userManager.FindByNameAsync(request.Username!);

        if (user != null && await userManager.CheckPasswordAsync(user, request.Password!))
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
            identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email!);
            identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    if (request.IsClientCredentialsGrantType())
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId!);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    throw new InvalidOperationException("The specified grant type is not supported.");
});
```

#### Database Issues
```powershell
# Reset database if needed
Remove-Item MrWho.db -ErrorAction SilentlyContinue
dotnet ef database update
```

#### SSL Certificate Issues
```powershell
# Trust development certificate
dotnet dev-certs https --trust
```

## 📚 Additional Resources

- [OpenIddict Documentation](https://documentation.openiddict.com/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/connect/)
- [ASP.NET Core Identity Documentation](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity)

## 🐘 Run with PostgreSQL via Docker Compose

This repository includes an alternative Docker Compose file to run the stack with PostgreSQL instead of SQL Server.

Prerequisites environment variables (example values):

```powershell
$env:POSTGRES_PASSWORD = "YourStrong!Passw0rd"; echo ""
$env:ASPNETCORE_Kestrel__Certificates__Default__Password = "your-cert-password"; echo ""
$env:LOCAL_HTTPS_CERT_DIR = (Resolve-Path "./certs").Path; echo ""
```

Start the Postgres-based stack:

```powershell
docker compose -f "docker-compose.postgres.yml" up --build -d; echo ""
```

Key settings used by the Postgres compose:
- Database provider: `Database:Provider=PostgreSql`
- Migrations assembly: `MrWho.Migrations.PostgreSql`
- Connection string: `Host=postgres;Database=MrWho;Username=postgres;Password=${POSTGRES_PASSWORD}`

Validate OIDC discovery endpoint (note the hyphen):
- https://localhost:7113/.well-known/openid-configuration

## 🐬 Run with MySQL via Docker Compose

Prerequisites environment variables (example values):

```powershell
$env:MYSQL_ROOT_PASSWORD = "YourStrong!Passw0rd"; echo ""
$env:ASPNETCORE_Kestrel__Certificates__Default__Password = "your-cert-password"; echo ""
$env:LOCAL_HTTPS_CERT_DIR = (Resolve-Path "./certs").Path; echo ""
```

Start the MySQL-based stack:

```powershell
docker compose -f "docker-compose.mysql.yml" up --build -d; echo ""
```

Key settings used by the MySQL compose:
- Database provider: `Database:Provider=MySql`
- Migrations assembly: `MrWho.Migrations.MySql`
- Connection string: `Server=mysql;Database=MrWho;User ID=root;Password=${MYSQL_ROOT_PASSWORD};`
- Optional: set `Database:MySql:Flavor` to `MariaDb` and `Database:MySql:Version` (e.g., `11.2.0`) if targeting MariaDB

Note: Compose files bind only HTTPS ports to the host. Internal service-to-service HTTP remains available within the Docker network.

## 🦭 Run with MariaDB via Docker Compose

Prerequisites environment variables (example values):

```powershell
$env:MARIADB_ROOT_PASSWORD = "YourStrong!Passw0rd"; echo ""
$env:ASPNETCORE_Kestrel__Certificates__Default__Password = "your-cert-password"; echo ""
$env:LOCAL_HTTPS_CERT_DIR = (Resolve-Path "./certs").Path; echo ""
```

Start the MariaDB-based stack:

```powershell
docker compose -f "docker-compose.mariadb.yml" up --build -d; echo ""
```

Key settings used by the MariaDB compose:
- Database provider: `Database:Provider=MySql`
- MariaDB flavor/version: `Database:MySql:Flavor=MariaDb`, `Database:MySql:Version=11.2.0`
- Migrations assembly: `MrWho.Migrations.MySql`
- Connection string: `Server=mariadb;Database=MrWho;User ID=root;Password=${MARIADB_ROOT_PASSWORD};`

Troubleshooting:
- If the MariaDB container logs: "Database is uninitialized and password option is not specified", set `MARIADB_ROOT_PASSWORD`.
- Easiest: copy `.env.example` to `.env`, set strong values, then rerun compose.