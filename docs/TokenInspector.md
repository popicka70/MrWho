# JWT Token Inspector

The JWT Token Inspector is a comprehensive tool for debugging and inspecting JWT tokens issued by the MrWho Identity Server. It provides both a web-based UI and REST API endpoints for token analysis.

## Features

### ?? Token Decoding
- Decode JWT tokens without validation
- Extract header, payload, and claims information
- Parse token expiration and validity times
- Identify token types (access token, ID token, etc.)

### ?? Token Introspection (OAuth 2.0 RFC 7662)
- Validate tokens against the identity server
- Check token active status
- Extract authorized scopes and client information
- Compliance with OAuth 2.0 token introspection standard

### ?? Current User Information
- Inspect currently authenticated user's token
- View all claims and permissions
- Analyze scopes and roles
- Check token expiration status

## Access Points

### Web Interface
- **Main UI**: `https://localhost:7113/identity/token-inspector`
- **Alternative URL**: `https://localhost:7113/identity/tokeninspector`
- **Admin Interface**: `https://localhost:7257/identity/token-inspector`

### API Endpoints

#### Decode Token (No Authentication Required)
```http
POST https://localhost:7113/identity/token-inspector/decode
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Introspect Token (Authentication Required)
```http
POST https://localhost:7113/identity/token-inspector/introspect
Authorization: Bearer <your-access-token>
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Current User Token Info (Authentication Required)
```http
GET https://localhost:7113/identity/token-inspector/current
Authorization: Bearer <your-access-token>
```

## Usage Examples

### 1. Web Interface Usage
1. Navigate to `https://localhost:7113/identity/token-inspector`
2. Paste your JWT token in the text area
3. Click "?? Decode Token" to analyze the token structure
4. Use "?? Introspect Token" for server-side validation
5. Click "?? Get Current Token" to inspect your current session

### 2. API Usage with PowerShell

```powershell
# Decode a token
$token = "your-jwt-token-here"
$body = @{ token = $token } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "https://localhost:7113/identity/token-inspector/decode" -Method POST -Body $body -ContentType "application/json"
$response | ConvertTo-Json -Depth 10
```

### 3. API Usage with curl

```bash
# Decode a token
curl -X POST https://localhost:7113/identity/token-inspector/decode \
  -H "Content-Type: application/json" \
  -d '{"token":"your-jwt-token-here"}'

# Introspect a token (requires authentication)
curl -X POST https://localhost:7113/identity/token-inspector/introspect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-access-token" \
  -d '{"token":"token-to-validate"}'
```

## Response Examples

### Decode Response
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-id"
  },
  "payload": {
    "iss": "https://localhost:7113",
    "sub": "user-id",
    "aud": ["api1", "api2"],
    "exp": 1705123456,
    "iat": 1705120000,
    "claims": [
      {"type": "email", "value": "user@example.com"},
      {"type": "scope", "value": "openid email profile"}
    ]
  },
  "validity": {
    "isValid": true,
    "isExpired": false,
    "validFrom": "2024-01-13 10:00:00 UTC",
    "validTo": "2024-01-13 11:00:00 UTC",
    "timeUntilExpiry": "00:45:30"
  },
  "metadata": {
    "tokenType": "access_token",
    "tokenLength": 1245,
    "claimsCount": 15
  }
}
```

### Introspection Response
```json
{
  "active": true,
  "client_id": "mrwho_admin_web",
  "username": "admin@mrwho.local",
  "scope": "openid email profile api.read api.write",
  "sub": "user-id",
  "aud": ["api1"],
  "iss": "https://localhost:7113",
  "exp": 1705123456,
  "iat": 1705120000,
  "token_type": "Bearer",
  "token_use": "access_token"
}
```

## Security Considerations

?? **Important Security Notes:**

1. **Development Only**: This tool is designed for development and debugging purposes
2. **Token Sensitivity**: Never use real production tokens in shared environments
3. **Network Security**: Ensure HTTPS is used for all token transmissions
4. **Authentication Required**: Some endpoints require valid authentication
5. **Logging**: Token operations may be logged for debugging purposes

## Integration with Admin Interface

The token inspector is integrated into the MrWho Admin interface:

1. **Navigation Menu**: Found under "Identity Server" ? "Token Inspector"
2. **Debug Pages**: Links to existing debug token pages
3. **Quick Actions**: One-click access to common token operations

## Troubleshooting

### Common Issues

1. **Token Not Recognized**
   - Ensure the token is a valid JWT format
   - Check that the token is not corrupted or truncated
   - Verify the token includes the correct header and signature

2. **Introspection Fails**
   - Ensure you have a valid access token for authentication
   - Check that the token being introspected is from the same issuer
   - Verify network connectivity to the identity server

3. **Current User Info Empty**
   - Ensure you are authenticated with the identity server
   - Check that your session hasn't expired
   - Verify cookies are enabled in your browser

### Debug Endpoints

Additional debug endpoints are available at:
- `https://localhost:7113/debug` - Debug endpoints discovery
- `https://localhost:7113/debug/admin-client-info` - Client configuration info
- `https://localhost:7113/debug/openiddict-scopes` - Available scopes

## Development Notes

The token inspector is implemented in:
- **Controller**: `MrWho\Controllers\TokenInspectorController.cs`
- **Admin Page**: `WrWhoAdmin.Web\Components\Pages\TokenInspector.razor`
- **Route Registration**: `MrWho\Extensions\WebApplicationExtensions.cs`

It uses the `System.IdentityModel.Tokens.Jwt` package for JWT parsing and validation.