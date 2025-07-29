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

## Architecture

The solution consists of the following projects:

- **MrWho.AppHost**: Aspire orchestration host
- **MrWho.ApiService**: OIDC provider and user management API
- **MrWho.Web**: Blazor frontend application
- **MrWho.ServiceDefaults**: Common Aspire service configurations

## Getting Started

### Prerequisites

- .NET 9 SDK
- SQL Server (or SQL Server LocalDB)
- Visual Studio 2022 or VS Code with C# Dev Kit

### Running the Application

1. **Start the Aspire Application**:
   ```powershell
   cd MrWho.AppHost
   dotnet run
   ```

2. **Access the Aspire Dashboard**: Open the URL shown in the console (typically `https://localhost:17000`)

3. **The API Service** will be available at the URL shown in the Aspire dashboard

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

## User Management Examples

### Create a New User

```http
POST /api/users
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "userName": "johndoe"
}
```

### Update User Information

```http
PUT /api/users/{userId}
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Smith",
  "email": "john.smith@example.com",
  "isActive": true
}
```

### Change Password

```http
POST /api/users/{userId}/change-password
Content-Type: application/json

{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!"
}
```

## OIDC Integration

### Client Configuration

The system comes with a pre-configured OIDC client:

- **Client ID**: `mrwho-client`
- **Client Secret**: `mrwho-secret`
- **Supported Grant Types**: 
  - Password Grant
  - Client Credentials Grant
- **Supported Scopes**: `email`, `profile`, `roles`

### Getting an Access Token (Password Grant)

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

### Response Example

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "email profile"
}
```

## Database Schema

The system uses Entity Framework Core with the following key entities:

- **ApplicationUser**: Extended IdentityUser with additional properties
- **OpenIddict Tables**: Applications, authorizations, scopes, and tokens
- **ASP.NET Identity Tables**: Users, roles, claims, etc.

## Configuration

### Connection Strings

The application uses Aspire's SQL Server integration. Connection strings are automatically managed by Aspire.

### Identity Options

Password requirements and user options are configured in `Program.cs`:

```csharp
options.Password.RequireDigit = true;
options.Password.RequireLowercase = true;
options.Password.RequireNonAlphanumeric = false;
options.Password.RequireUppercase = true;
options.Password.RequiredLength = 6;
```

## Development

### Adding New OIDC Clients

To add new OIDC clients, modify the seeding logic in `Program.cs`:

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

To add new user properties:

1. Update the `ApplicationUser` model
2. Create a new EF migration: `dotnet ef migrations add AddNewUserProperty`
3. Update the DTOs and UserService accordingly

## Security Considerations

- ? Passwords are hashed using ASP.NET Core Identity
- ? JWT tokens are signed with development certificates (use proper certificates in production)
- ? User accounts can be activated/deactivated
- ? Email confirmation support (currently auto-confirmed for simplicity)
- ?? Use HTTPS in production
- ?? Replace development certificates with production certificates
- ?? Implement proper logging and monitoring

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

## Troubleshooting

### Common Issues

1. **Database Connection**: Ensure SQL Server is running and accessible
2. **Migration Issues**: Run `dotnet ef database update` if needed
3. **Port Conflicts**: Check Aspire dashboard for correct service URLs

### Logs

Check the Aspire dashboard for detailed logs from all services.

## License

This project is for educational purposes. Modify as needed for your specific requirements.