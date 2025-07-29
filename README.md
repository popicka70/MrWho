# MrWho OIDC Service Provider

This is a complete OIDC (OpenID Connect) service provider built with .NET 9, ASP.NET Core Identity, OpenIddict, and SQL Server. It provides user management capabilities and acts as an identity provider for other applications.

## Features

- ? **OIDC Provider**: Full OpenID Connect support with token endpoint
- ? **User Management**: Complete CRUD operations for users
- ? **Password Management**: Secure password creation and updates
- ? **SQL Server Storage**: Entity Framework Core with SQL Server
- ? **ASP.NET Core Identity**: Built-in security and user management
- ? **OpenIddict Integration**: Standards-compliant OIDC implementation
- ? **Aspire Integration**: Full .NET Aspire support with service discovery
- ? **Database Migrations**: Proper Entity Framework migrations with OpenIddict support

## Architecture

The solution consists of the following projects:

- **MrWho.AppHost**: Aspire orchestration host
- **MrWho.ApiService**: OIDC provider and user management API
- **MrWho.Web**: Blazor frontend application
- **MrWho.ServiceDefaults**: Common Aspire service configurations

## Recent Fixes

### ? Database Migration Issue Resolved

**Problem**: `Invalid object name 'OpenIddictApplications'` error when starting the application.

**Root Cause**: The application was using `EnsureCreatedAsync()` which doesn't apply Entity Framework migrations.

**Solution**:
- ? **Replaced EnsureCreatedAsync() with MigrateAsync()**: Properly applies all migrations including OpenIddict tables
- ? **Added comprehensive logging**: Better visibility into database initialization process
- ? **Enhanced error handling**: Graceful handling of database initialization errors
- ? **Created database management script**: PowerShell script for database operations

## Getting Started

### Prerequisites

- .NET 9 SDK
- SQL Server (or SQL Server LocalDB)
- Visual Studio 2022 or VS Code with C# Dev Kit

### Quick Start

1. **Clone and navigate to the project**:
   ```powershell
   Set-Location MrWho.AppHost
   ```

2. **Start the Aspire Application**:
   ```powershell
   dotnet run
   ```

3. **The application will automatically**:
   - Connect to SQL Server via Aspire service discovery
   - Apply all database migrations (including OpenIddict tables)
   - Seed default admin user and OIDC client
   - Start all services

4. **Access the Aspire Dashboard**: Open the URL shown in the console (typically `https://localhost:17000`)

### Database Management

#### Automatic (Recommended)

The application automatically handles database setup when you start it. Check the logs in the Aspire dashboard for initialization progress.

#### Manual Database Operations

Use the provided PowerShell script for manual database management:

```powershell
# Check database status
.\Manage-Database.ps1 -Action status

# Apply migrations manually
.\Manage-Database.ps1 -Action migrate

# Reset database (WARNING: Deletes all data)
.\Manage-Database.ps1 -Action reset

# Start application for seeding
.\Manage-Database.ps1 -Action seed

# Show help
.\Manage-Database.ps1 -Action help
```

### Default Credentials

A default admin user is automatically created:
- **Email**: `admin@mrwho.com`
- **Password**: `Admin123!`

## API Endpoints

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | Get all users (with pagination) |
| GET | `/api/users/{id}` | Get user by ID |
| GET | `/api/users/by-email/{email}` | Get user by email |
| POST | `/api/users` | Create new user |
| PUT | `/api/users/{id}` | Update user |
| POST | `/api/users/{id}/change-password` | Change user password |
| DELETE | `/api/users/{id}` | Delete user |

### OIDC Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/connect/token` | Token endpoint for OIDC |

### Test Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/test/public` | Public endpoint (no auth) |
| GET | `/api/test/protected` | Protected endpoint (requires token) |
| GET | `/api/test/user-info` | User information endpoint |

## Testing

### Automated Testing Script

```powershell
.\Test-MrWhoApi.ps1
```

This script will:
- ? Test public endpoints
- ? Obtain access tokens
- ? Test protected endpoints
- ? Verify user management APIs
- ? Create test users

### Manual Testing

#### Get Access Token
```http
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&
client_id=mrwho-client&
client_secret=mrwho-secret&
username=admin@mrwho.com&
password=Admin123!&
scope=email profile
```

#### Use Token to Access Protected Endpoint
```http
GET /api/test/protected
Authorization: Bearer {your_access_token}
```

### PowerShell Testing Examples

```powershell
# Test public endpoint
Invoke-RestMethod -Uri "https://localhost:7001/api/test/public"

# Get access token
$body = @{
    grant_type = "password"
    client_id = "mrwho-client"
    client_secret = "mrwho-secret"
    username = "admin@mrwho.com"
    password = "Admin123!"
    scope = "email profile"
}
$token = Invoke-RestMethod -Uri "https://localhost:7001/connect/token" -Method Post -Body $body

# Test protected endpoint
$headers = @{ Authorization = "Bearer $($token.access_token)" }
Invoke-RestMethod -Uri "https://localhost:7001/api/test/protected" -Headers $headers

# Create new user
$newUser = @{
    email = "test@example.com"
    password = "TestUser123!"
    firstName = "Test"
    lastName = "User"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:7001/api/users" -Method Post -Body $newUser -ContentType "application/json"
```

## Database Schema

The system uses Entity Framework Core with the following key entities:

### Identity Tables
- **ApplicationUser**: Extended IdentityUser with additional properties
- **ASP.NET Identity Tables**: Users, roles, claims, etc.

### OpenIddict Tables
- **OpenIddictApplications**: OIDC client applications
- **OpenIddictAuthorizations**: User authorizations  
- **OpenIddictScopes**: Available scopes
- **OpenIddictTokens**: Issued tokens

### Database Migration History
- **__EFMigrationsHistory**: Entity Framework migration tracking

## Configuration

### OIDC Client Configuration

The system comes with a pre-configured OIDC client:

- **Client ID**: `mrwho-client`
- **Client Secret**: `mrwho-secret`
- **Supported Grant Types**: 
  - Password Grant
  - Client Credentials Grant
- **Supported Scopes**: `email`, `profile`, `roles`

### Connection Strings

The application uses Aspire's SQL Server integration. Connection strings are automatically managed by Aspire and provided via service discovery.

### Identity Options

Password requirements configured in `Program.cs`:
```csharp
options.Password.RequireDigit = true;
options.Password.RequireLowercase = true;
options.Password.RequireNonAlphanumeric = false;
options.Password.RequireUppercase = true;
options.Password.RequiredLength = 6;
```

## Development

### Database Migrations

Create new migrations when updating the data model:

```powershell
Set-Location MrWho.ApiService
dotnet ef migrations add YourMigrationName
dotnet ef database update  # Optional - app will auto-migrate on startup
```

### Adding New OIDC Clients

Modify the seeding logic in `Program.cs`:

```csharp
await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
{
    ClientId = "your-client-id",
    ClientSecret = "your-client-secret",
    DisplayName = "Your Application Name",
    Permissions = { /* permissions */ }
});
```

### Extending User Properties

1. Update `ApplicationUser` model
2. Create migration: `dotnet ef migrations add AddNewUserProperty`
3. Update DTOs and `UserService`
4. Restart application (auto-migration will apply changes)

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - ? Ensure SQL Server is running
   - ? Check Aspire dashboard for service status
   - ? Use `.\Manage-Database.ps1 -Action status` to verify connection

2. **Migration Errors**
   - ? Use `.\Manage-Database.ps1 -Action migrate` to apply manually
   - ? Check Entity Framework logs in Aspire dashboard
   - ? Ensure no conflicting database connections

3. **OpenIddict Table Errors**
   - ? **Fixed**: Application now uses `MigrateAsync()` instead of `EnsureCreatedAsync()`
   - ? Verify `builder.UseOpenIddict()` is called in `ApplicationDbContext`
   - ? Check migration files include OpenIddict tables

4. **OIDC Token Errors**
   - ? Verify client credentials (`mrwho-client` / `mrwho-secret`)
   - ? Check user credentials (`admin@mrwho.com` / `Admin123!`)
   - ? Ensure user account is active (`IsActive = true`)

### Logs and Monitoring

- **Aspire Dashboard**: Real-time logs from all services
- **Database Initialization**: Detailed logging during startup
- **Migration Status**: Logged during application startup
- **Seeding Process**: Logged with success/failure status

### Database Reset

If you encounter persistent database issues:

```powershell
# WARNING: This deletes all data
.\Manage-Database.ps1 -Action reset
```

## Security Considerations

- ? Passwords hashed with ASP.NET Core Identity
- ? JWT tokens signed with development certificates
- ? User account activation/deactivation support
- ? Email confirmation support (auto-confirmed for simplicity)
- ?? Use HTTPS in production
- ?? Replace development certificates with production certificates
- ?? Implement proper logging and monitoring
- ?? Use secure connection strings in production

## Future Enhancements

- [ ] External identity providers (Google, Microsoft, etc.)
- [ ] Authorization endpoint for web-based authentication flows
- [ ] User info endpoint
- [ ] Refresh token support
- [ ] Role-based access control
- [ ] Email verification workflow
- [ ] Password reset functionality
- [ ] Audit logging
- [ ] Multi-factor authentication

## License

This project is for educational purposes. Modify as needed for your specific requirements.