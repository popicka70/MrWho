# MrWho OIDC Server - Essential Data Setup

## Overview
The MrWho OIDC server now automatically creates essential data that must always be present for proper operation. This includes the admin realm, admin client, and admin user with preset credentials.

## Essential Data Created

### 1. Admin Realm
- **Name**: `admin`
- **Display Name**: "MrWho Administration"
- **Description**: "Administrative realm for MrWho OIDC server management"
- **Status**: Enabled
- **Token Lifetimes**:
  - Access Token: 60 minutes
  - Refresh Token: 30 days
  - Authorization Code: 10 minutes

### 2. Admin Client
- **Client ID**: `mrwho_admin_web`
- **Client Secret**: `MrWhoAdmin2024!SecretKey`
- **Name**: "MrWho Admin Web Application"
- **Description**: "Official web administration interface for MrWho OIDC server"
- **Type**: Confidential
- **Flows Enabled**:
  - Authorization Code Flow: ?
  - Client Credentials Flow: ?
  - Password Flow: ?
  - Refresh Token Flow: ?
- **Security Settings**:
  - Requires PKCE: ?
  - Requires Client Secret: ?

#### Redirect URIs
- `https://localhost:7257/signin-oidc`
- `https://localhost:7257/callback`

#### Post-Logout URIs
- `https://localhost:7257/`
- `https://localhost:7257/signout-callback-oidc`

#### Scopes
- `openid`
- `email`
- `profile`
- `roles`

### 3. Admin User
- **Username**: `admin@mrwho.local`
- **Email**: `admin@mrwho.local`
- **Password**: `MrWhoAdmin2024!`
- **Email Confirmed**: ?

## Application Configuration

### MrWho OIDC Server (Port 7113)
The MrWho API runs on `https://localhost:7113` and provides:
- Authorization Endpoint: `https://localhost:7113/connect/authorize`
- Token Endpoint: `https://localhost:7113/connect/token`
- UserInfo Endpoint: `https://localhost:7113/connect/userinfo`
- End Session Endpoint: `https://localhost:7113/connect/logout`
- Discovery Document: `https://localhost:7113/.well-known/openid-configuration`

### MrWhoAdmin.Web Application (Port 7257)  
The admin web application runs on `https://localhost:7257` and is configured to:
- Use the `mrwho_admin_web` client
- Authenticate against the MrWho OIDC server
- Redirect properly to the fixed port URLs (no Aspire notation)

## Usage Instructions

### 1. Starting the Applications
```bash
# Start MrWho OIDC Server (runs database migrations and seeding)
cd MrWho
dotnet run

# Start MrWhoAdmin.Web (in separate terminal)
cd WrWhoAdmin.Web  
dotnet run
```

### 2. Accessing the Admin Interface
1. Navigate to `https://localhost:7257`
2. Click "Login" or access a protected page
3. You'll be redirected to the MrWho OIDC login page
4. Use the admin credentials:
   - **Username**: `admin@mrwho.local`
   - **Password**: `MrWhoAdmin2024!`
5. After successful authentication, you'll be redirected back to the admin interface

### 3. Debug Endpoints
The MrWho API provides debug endpoints to verify the setup:

- **Admin Client Info**: `https://localhost:7113/debug/admin-client-info`
- **Essential Data**: `https://localhost:7113/debug/essential-data`
- **DB Client Config**: `https://localhost:7113/debug/db-client-config`

## Data Persistence
All essential data is automatically created when the MrWho application starts:
- Database is created if it doesn't exist
- Essential data is seeded only if it doesn't already exist
- Existing data is preserved and not overwritten
- OpenIddict client registrations are synchronized on startup

## Security Considerations
- The admin client uses a strong, randomly generated client secret
- PKCE is enabled for additional security
- The admin user password meets complexity requirements
- All communication uses HTTPS (development certificates)
- Tokens have reasonable lifetimes for development/testing

## Production Deployment
For production deployment, ensure:
1. Change the admin user password
2. Update client secret to production-grade secret
3. Configure proper redirect URIs for your production domains
4. Enable HTTPS metadata verification
5. Use production certificates instead of development certificates
6. Configure proper logging and monitoring

## Troubleshooting

### Common Issues
1. **Port conflicts**: Ensure ports 7113 and 7257 are available
2. **HTTPS certificate issues**: Accept development certificates when prompted
3. **Database issues**: The application will create the database automatically
4. **Authentication failures**: Check the debug endpoints to verify client configuration

### Log Analysis
Both applications provide comprehensive logging for authentication events:
- Check console output for initialization messages
- Authentication events are logged with detailed information
- Use debug endpoints to verify configuration

## Additional Test Data
Besides the essential admin data, the system also creates:
- Default realm with postman_client (for backwards compatibility)
- Test user: `test@example.com` / `Test123!`
- Sample realms and clients (if seeding is enabled)

This ensures the system is ready for immediate use and testing.