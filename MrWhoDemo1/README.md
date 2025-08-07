# MrWho Demo Application 1

This is a demo Razor Pages application that showcases authentication integration with the MrWho OIDC Server.

## Features

- **Authentication via MrWho OIDC Server**: Uses OpenID Connect for user authentication
- **Token Display**: Shows detailed information about access tokens, refresh tokens, and ID tokens
- **Claims Inspection**: Displays all user claims received from the identity server
- **Secure Pages**: Home page requires authentication

## Demo Credentials

- **Username**: `demo1@example.com`
- **Password**: `Demo123`

## Application URLs

- **Demo App**: https://localhost:7037
- **MrWho OIDC Server**: https://localhost:7113
- **MrWho Admin Interface**: https://localhost:7257

## Getting Started

1. **Start the applications** using the AppHost:
   ```bash
   cd MrWhoAdmin.AppHost
   dotnet run
   ```

2. **Access the demo application**:
   - Navigate to https://localhost:7037
   - You'll be redirected to login since the home page requires authentication

3. **Login with demo credentials**:
   - Click "Login with MrWho"
   - Use the demo credentials: `demo1@example.com` / `Demo123`
   - You'll be redirected back to the demo app

4. **Explore token information**:
   - The home page displays comprehensive token and user information
   - View access tokens, refresh tokens, ID tokens, and all claims

## Technical Details

### Client Configuration

- **Client ID**: `mrwho_demo1`
- **Client Secret**: `Demo1Secret2024!`
- **Realm**: `demo`
- **Client Type**: Confidential
- **Flows**: Authorization Code Flow with PKCE
- **Scopes**: `openid`, `profile`, `email`, `roles`, `offline_access`

### Authentication Configuration

The application uses:
- **ASP.NET Core Authentication** with OpenID Connect
- **Cookie Authentication** for session management
- **PKCE** for additional security
- **Token Persistence** for display purposes

### Debug Endpoints

Access debug information at the MrWho OIDC Server:
- **Demo1 Client Info**: https://localhost:7113/debug/demo1-client-info
- **All Debug Endpoints**: https://localhost:7113/debug

## Project Structure

```
MrWhoDemo1/
??? Pages/
?   ??? Account/           # Login/Logout pages
?   ??? Shared/           # Layout files
?   ??? Index.cshtml      # Home page with token display
??? Program.cs            # Authentication configuration
??? MrWhoDemo1.csproj    # Project file
```

## Key Components

### Authentication Setup (Program.cs)
- Configures OpenID Connect with MrWho OIDC Server
- Sets up cookie authentication for session management
- Enables PKCE and token saving

### Home Page (Index.cshtml)
- Requires authentication (`[Authorize]` attribute)
- Displays user information and claims
- Shows all tokens (access, refresh, ID)
- Provides logout functionality

### Account Pages
- **Login**: Initiates OpenID Connect challenge
- **Logout**: Signs out from both local app and OIDC provider

## Security Features

- **PKCE (Proof Key for Code Exchange)**: Enhanced security for authorization code flow
- **HTTPS**: All communication uses HTTPS
- **Secure Cookies**: Authentication cookies with proper security settings
- **Token Validation**: Proper validation of tokens from the OIDC server

## Demo Data

The MrWho OIDC Server automatically creates:
- **Demo Realm**: Named "demo" for demo applications
- **Demo1 Client**: Pre-configured for this application
- **Demo1 User**: `demo1@example.com` with password `demo1`

## Troubleshooting

### Common Issues

1. **Redirect URI Mismatch**: Ensure the demo app runs on port 7037
2. **HTTPS Certificate**: Accept development certificates when prompted
3. **Authentication Failures**: Check the debug endpoints for client configuration

### Logs

Check console output for authentication events and any errors during the OIDC flow.

## Development Notes

- The application uses Razor Pages with .NET 9
- Bootstrap 5 with Bootstrap Icons for UI
- Aspire for service orchestration and dependencies
- Development certificates for HTTPS

This demo application serves as a reference implementation for integrating with the MrWho OIDC Server.