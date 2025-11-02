# Go Web Client Demo

This is a sample Go web application demonstrating integration with MrWhoOidc as an OpenID Connect Provider. It showcases a **confidential client** implementation using Authorization Code flow with PKCE and native Go libraries.

## Technology Stack

- **Go 1.21+**: Native Go web application
- **Authentication**: coreos/go-oidc v3 library
- **Client Type**: Confidential (requires client secret)
- **OIDC Flows**: Authorization Code with PKCE, token refresh, logout
- **HTTP**: Native net/http with secure session management

## Prerequisites

### Option 1 - Docker Compose (Recommended)

- Docker Desktop or Docker Engine with Docker Compose V2
- Git

### Option 2 - Local Development

- Go 1.21 or later
- Docker (for running MrWhoOidc)
- Git

## Quick Start with Docker Compose

This is the fastest way to see the demo in action.

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/MrWhoOidc.git
cd MrWhoOidc/MrWho/demos/go-client
```

### 2. Start MrWhoOidc and Demo Client

```bash
# Start both the OIDC provider and demo client
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d

# Check logs
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml logs -f go-demo
```

### 3. Register the Client

1. Open the Admin UI at <https://localhost:8443/admin>
2. Navigate to **Clients** → **Create Client**
3. Fill in the form:
   - **Client ID**: `go-demo`
   - **Client Name**: `Go Web Client Demo`
   - **Client Type**: `Confidential`
   - **Grant Types**: `authorization_code`, `refresh_token`
   - **Redirect URIs**: `https://localhost:5080/callback`
   - **Post Logout Redirect URIs**: `https://localhost:5080/`
   - **Scopes**: `openid`, `profile`, `email`
4. Save the client and **copy the generated client secret**

### 4. Configure the Client Secret

Edit `config.json` and update the client secret:

```json
{
  "issuer": "https://localhost:8443",
  "client_id": "go-demo",
  "client_secret": "your-secret-from-admin-ui",
  "redirect_uri": "https://localhost:5080/callback",
  "post_logout_redirect_uri": "https://localhost:5080/",
  "scopes": ["openid", "profile", "email"],
  "server_port": 5080
}
```

Or use environment variables (see Configuration Reference below).

Restart the demo client:

```bash
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml restart go-demo
```

### 5. Test the Application

1. Navigate to <https://localhost:5080>
2. Click **Login**
3. You'll be redirected to MrWhoOidc login page
4. Enter credentials (default: `admin@example.com` / `Admin123!`)
5. After successful authentication, you'll see user info
6. Test **Logout** to verify logout flow

## Local Development (Without Docker)

This approach lets you run the demo natively on your machine.

### 1. Start MrWhoOidc

```bash
cd MrWhoOidc/MrWho
docker compose up -d
```

### 2. Install Dependencies

```bash
cd demos/go-client
go mod download
```

### 3. Configure the Demo

Copy `config.example.json` to `config.json` and update:

```json
{
  "issuer": "https://localhost:8443",
  "client_id": "go-demo",
  "client_secret": "your-secret-from-admin-ui",
  "redirect_uri": "https://localhost:5080/callback",
  "post_logout_redirect_uri": "https://localhost:5080/",
  "scopes": ["openid", "profile", "email"],
  "server_port": 5080
}
```

### 4. Register the Client

Follow step 3 from the Docker Compose guide above.

### 5. Run the Application

```bash
go run main.go
```

Or build and run:

```bash
go build -o go-web-client
./go-web-client
```

### 6. Test the Application

Navigate to <https://localhost:5080>

## Configuration Reference

The demo supports JSON configuration (`config.json`) or environment variables:

| Environment Variable | config.json Key | Default | Description |
|---------------------|----------------|---------|-------------|
| `OIDC_ISSUER` | `issuer` | `https://localhost:8443` | OIDC provider base URL |
| `OIDC_CLIENT_ID` | `client_id` | `go-demo` | Client identifier |
| `OIDC_CLIENT_SECRET` | `client_secret` | *(required)* | Client secret from Admin UI |
| `OIDC_REDIRECT_URI` | `redirect_uri` | `https://localhost:5080/callback` | Callback URI |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | `post_logout_redirect_uri` | `https://localhost:5080/` | Post-logout URI |
| `OIDC_SCOPES` | `scopes` | `["openid","profile","email"]` | Requested scopes (JSON array) |
| `SERVER_PORT` | `server_port` | `5080` | HTTP server port |

**Priority**: Environment variables override `config.json` values.

### Configuration File (config.json)

```json
{
  "issuer": "https://localhost:8443",
  "client_id": "go-demo",
  "client_secret": "your-client-secret",
  "redirect_uri": "https://localhost:5080/callback",
  "post_logout_redirect_uri": "https://localhost:5080/",
  "scopes": ["openid", "profile", "email"],
  "server_port": 5080
}
```

See [CONFIG.md](./CONFIG.md) for detailed configuration guide.

## Expected Behavior

### After Successful Login

You should see a page displaying:

- **User Information**: Name, email, subject
- **Token Information**: Expiration time
- **Logout Button**: To end the session

### Authentication Flow

1. Click **Login** → Redirects to `/auth` handler
2. Generate PKCE challenge (code_verifier and code_challenge)
3. Redirect to MrWhoOidc `/authorize` endpoint with:
   - `response_type=code`
   - `code_challenge` and `code_challenge_method=S256`
   - `redirect_uri`, `scope`, `state`, `nonce`
4. User authenticates at MrWhoOidc
5. Redirect back to `/callback` with authorization code
6. Exchange code for tokens using client secret and PKCE verifier
7. Verify ID token signature and claims
8. Store tokens in server-side session (cookie-based)
9. Redirect to homepage showing user info

### Logout Flow

1. Click **Logout** → Initiates logout
2. Clear server-side session
3. Redirect to MrWhoOidc `/logout` endpoint with `id_token_hint` and `post_logout_redirect_uri`
4. MrWhoOidc clears session
5. Redirect back to app homepage

### Session Management

- **Cookie-Based Sessions**: Encrypted session cookie
- **Session Storage**: In-memory (for demo purposes)
- **Session Timeout**: 1 hour (configurable)
- **CSRF Protection**: State parameter validation

## Troubleshooting

### "Unauthorized" Error

**Cause**: Client not registered or client secret mismatch.

**Solution**:

- Verify client is registered in Admin UI
- Check `client_id` matches registration
- Verify `client_secret` is correct
- Check redirect URIs match exactly

### "Invalid Redirect URI" Error

**Cause**: Redirect URI not registered in Admin UI.

**Solution**:

- Ensure `https://localhost:5080/callback` is listed in client's Redirect URIs
- Check for typos (trailing slashes, http vs https)

### SSL Certificate Errors

**Cause**: MrWhoOidc uses self-signed certificate.

**Solution**:

- Trust the certificate in browser (proceed past warning)
- Or add certificate to system trust store:

```bash
# Linux
sudo cp certs/aspnetapp.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/aspnetapp.crt
```

### "Connection Refused" to MrWhoOidc

**Cause**: MrWhoOidc container not running.

**Solution**:

```bash
# Check MrWhoOidc is running
docker ps | grep mrwho-oidc

# Start if not running
cd MrWhoOidc/MrWho
docker compose up -d
```

### Token Validation Errors

**Cause**: ID token signature validation failed.

**Solution**:

- Verify OIDC provider's JWKS endpoint is accessible
- Check system time is synchronized (JWT timestamps are time-sensitive)
- Ensure issuer URL matches exactly

### Session Not Persisting

**Cause**: Session storage issues or cookie problems.

**Solution**:

- Check browser accepts cookies from `localhost`
- Verify session encryption key is set
- Check server logs for session storage errors

## Code Walkthrough

### Configuration Loading (main.go)

```go
func loadConfig() (*Config, error) {
    // Read config file
    data, err := os.ReadFile("config.json")
    if err != nil {
        return nil, err
    }
    
    var config Config
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    
    // Override with environment variables
    if issuer := os.Getenv("OIDC_ISSUER"); issuer != "" {
        config.Issuer = issuer
    }
    // ... (other env vars)
    
    return &config, nil
}
```

### OIDC Provider Setup

```go
ctx := context.Background()
provider, err := oidc.NewProvider(ctx, config.Issuer)
if err != nil {
    log.Fatal(err)
}

oauth2Config := oauth2.Config{
    ClientID:     config.ClientID,
    ClientSecret: config.ClientSecret,
    RedirectURL:  config.RedirectURI,
    Endpoint:     provider.Endpoint(),
    Scopes:       config.Scopes,
}

verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
```

### Login Handler

```go
func handleLogin(w http.ResponseWriter, r *http.Request) {
    // Generate PKCE challenge
    codeVerifier := generateCodeVerifier()
    codeChallenge := generateCodeChallenge(codeVerifier)
    
    // Generate state and nonce
    state := generateRandomString(32)
    nonce := generateRandomString(32)
    
    // Store in session
    session := getSession(r)
    session.CodeVerifier = codeVerifier
    session.State = state
    session.Nonce = nonce
    saveSession(w, session)
    
    // Build authorization URL
    authURL := oauth2Config.AuthCodeURL(state,
        oauth2.SetAuthURLParam("code_challenge", codeChallenge),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
        oauth2.SetAuthURLParam("nonce", nonce),
    )
    
    http.Redirect(w, r, authURL, http.StatusFound)
}
```

### Callback Handler

```go
func handleCallback(w http.ResponseWriter, r *http.Request) {
    // Validate state
    session := getSession(r)
    if r.URL.Query().Get("state") != session.State {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }
    
    // Exchange code for tokens
    ctx := context.Background()
    code := r.URL.Query().Get("code")
    token, err := oauth2Config.Exchange(ctx, code,
        oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier),
    )
    if err != nil {
        http.Error(w, "Token exchange failed", http.StatusInternalServerError)
        return
    }
    
    // Verify ID token
    rawIDToken, ok := token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "No id_token", http.StatusInternalServerError)
        return
    }
    
    idToken, err := verifier.Verify(ctx, rawIDToken)
    if err != nil {
        http.Error(w, "Token verification failed", http.StatusUnauthorized)
        return
    }
    
    // Extract claims
    var claims struct {
        Sub   string `json:"sub"`
        Name  string `json:"name"`
        Email string `json:"email"`
        Nonce string `json:"nonce"`
    }
    if err := idToken.Claims(&claims); err != nil {
        http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
        return
    }
    
    // Validate nonce
    if claims.Nonce != session.Nonce {
        http.Error(w, "Invalid nonce", http.StatusBadRequest)
        return
    }
    
    // Save user info to session
    session.IDToken = rawIDToken
    session.AccessToken = token.AccessToken
    session.RefreshToken = token.RefreshToken
    session.UserInfo = claims
    saveSession(w, session)
    
    http.Redirect(w, r, "/", http.StatusFound)
}
```

## Next Steps

- **Explore Admin UI**: Manage clients, users, scopes at <https://localhost:8443/admin>
- **Read Documentation**: See [MrWhoOidc docs](../../docs/) and [CONFIG.md](./CONFIG.md)
- **Try Other Demos**: Check out .NET MVC and React SPA demos
- **Deploy to Production**: Review [deployment guide](../../docs/deployment-guide.md)

## Support

- **Issues**: <https://github.com/yourusername/MrWhoOidc/issues>
- **Documentation**: <https://github.com/yourusername/MrWhoOidc/tree/main/MrWho/docs>
