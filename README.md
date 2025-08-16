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
- Docker Desktop (for local PostgreSQL)

## 📦 Installation & Setup

### 1. Clone and Navigate to Project
```powershell
Set-Location MrWho
```

### 2. Restore Dependencies
```powershell
dotnet restore
```

### 3. Start local PostgreSQL with Docker Compose
This repo ships a simple compose file for a persistent local PostgreSQL database.

- Credentials:
  - Host: localhost
  - Port: 5432
  - Database: mrwho
  - Username: mrwho
  - Password: ChangeMe123!

Start/stop database:
```powershell
docker compose -f "docker-compose.db.yml" up -d; echo ""
# To stop: docker compose -f "docker-compose.db.yml" down; echo ""
```

Connection string to use in development:
```
Host=localhost;Port=5432;Database=mrwho;Username=mrwho;Password=ChangeMe123!
```

> appsettings.Development.json in MrWho is already updated to use this connection string.

### 4. Initialize Database Schema (EF Migrations)
```powershell
# Ensure the PostgreSQL provider is selected via appsettings.Development.json / code
# Apply migrations
cd "MrWho"; dotnet ef database update; cd ..; echo ""
```

### 5. Run the Application
```powershell
dotnet run --project "MrWho/MrWho.csproj"; echo ""
```

The application will start and be available at:
- **HTTPS**: `https://localhost:7113`

## 🐘 Run with PostgreSQL via Docker Compose (Full stack examples)

This repository also previously included compose variants. For local DB only, use `docker-compose.db.yml` above.

Key settings when targeting Postgres:
- Database provider: `PostgreSql`
- Migrations assembly: `MrWho.Migrations.PostgreSql`
- Connection string: `Host=localhost;Port=5432;Database=mrwho;Username=mrwho;Password=ChangeMe123!`

Validate OIDC discovery endpoint (note the hyphen):
- https://localhost:7113/.well-known/openid-configuration

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

$response = Invoke-RestMethod -Uri "https://localhost:7113/connect/token" -Method POST -ContentType "application/x-www-form-urlencoded" -Body $clientCredentialsBody

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

$response = Invoke-RestMethod -Uri "https://localhost:7113/connect/token" -Method POST -ContentType "application/x-www-form-urlencoded" -Body $passwordGrantBody

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

$userInfo = Invoke-RestMethod -Uri "https://localhost:7113/connect/userinfo" -Method GET -Headers $headers
$userInfo | ConvertTo-Json -Depth 3
```

### Method 2: cURL

#### Client Credentials Grant
```bash
curl -X POST https://localhost:7113/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=postman_client&client_secret=postman_secret&scope=email profile"
```

#### Password Grant
```bash
curl -X POST https://localhost:7113/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=postman_client&client_secret=postman_secret&username=test@example.com&password=Test123!&scope=email profile"
```

### Method 3: Postman

1. **Create a new collection** called "MrWho OIDC Tests"

2. **Add Token Endpoint Request**:
   - **Method**: POST
   - **URL**: `https://localhost:7113/connect/token`
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

- If migrations fail, ensure the Postgres container is healthy: `docker ps`, `docker logs mrwho-postgres`.
- Ensure your connection string matches the credentials above.
- Validate discovery endpoint path uses hyphen: `/.well-known/openid-configuration`.

## 📚 Additional Resources

- [OpenIddict Documentation](https://documentation.openiddict.com/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/connect/)
- [ASP.NET Core Identity Documentation](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity)