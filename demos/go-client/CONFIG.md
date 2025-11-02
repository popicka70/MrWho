# Configuration Guide

The Go demo uses a JSON configuration file instead of environment variables.

## Quick Setup

1. Copy the example configuration:
   ```bash
   cp config.example.json config.json
   ```

2. Edit `config.json` with your client credentials from MrWhoOidc Admin UI

## Configuration File: `config.json`

```json
{
  "issuer": "https://localhost:8443",
  "client_id": "go-demo",
  "client_secret": "your-client-secret-from-admin-ui",
  "redirect_url": "http://localhost:5080/callback",
  "scopes": [
    "openid",
    "profile",
    "email",
    "offline_access"
  ],
  "use_pkce": true,
  "listen_addr": ":5080"
}
```

## Configuration Options

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `issuer` | **Yes** | - | OIDC provider URL (e.g., `https://localhost:8443`) |
| `client_id` | **Yes** | - | Client ID from Admin UI |
| `client_secret` | **Yes** | - | Client Secret from Admin UI |
| `redirect_url` | No | `http://localhost:5080/callback` | OAuth2 redirect URI |
| `scopes` | No | `["openid", "profile", "offline_access"]` | Requested scopes |
| `use_pkce` | No | `true` | Enable PKCE for enhanced security |
| `listen_addr` | No | `:5080` | Server listen address |

## Client Registration Instructions

1. Start MrWhoOidc:
   ```bash
   docker compose up -d
   ```

2. Access Admin UI: https://localhost:8443/admin

3. Login with default credentials:
   - Username: `admin`
   - Password: `Admin123!`

4. Navigate to **Client Management** → **Create Client**

5. Configure the client:
   - **Client ID**: `go-demo`
   - **Client Type**: Confidential
   - **Grant Types**: Authorization Code
   - **Redirect URIs**: `http://localhost:5080/callback`
   - **Post Logout Redirect URIs**: `http://localhost:5080/`
   - **Allowed Scopes**: `openid`, `profile`, `email`, `offline_access`
   - **PKCE Required**: Yes (recommended)

6. Copy the generated **Client Secret**

7. Update `config.json` with the client secret

8. Run the demo:
   ```bash
   go run main.go
   ```

9. Access the demo: http://localhost:5080

## Custom Configuration File Path

You can specify a different configuration file using the `MRWHO_GO_WEB_CONFIG` environment variable:

```bash
export MRWHO_GO_WEB_CONFIG=/path/to/custom/config.json
go run main.go
```

## Security Notes

- **Never commit `config.json`** with real secrets to version control
- `config.json` is included in `.gitignore`
- Use `config.example.json` as a template
- Rotate client secrets regularly (recommended: every 90 days)
- Enable PKCE (`use_pkce: true`) for enhanced security
- Use HTTPS in production

## Troubleshooting

### "issuer and client_id are required"

Ensure `config.json` exists and contains valid `issuer` and `client_id` values.

### "failed to connect to issuer"

- Verify MrWhoOidc is running: `docker compose ps`
- Check the issuer URL is correct: `https://localhost:8443`
- Ensure certificate is trusted (or accept browser warning)

### "invalid_client" error

- Verify client credentials are correct in `config.json`
- Ensure client is registered in Admin UI
- Check redirect URI matches exactly

### "invalid_grant" error

- Check redirect URI in config matches Admin UI
- Verify scopes are allowed for the client
- Ensure authorization code hasn't expired

## See Also

- [Go Demo README](README.md) - Main demo documentation
- [MrWhoOidc Documentation](../../docs/) - OIDC provider documentation
