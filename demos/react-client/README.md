# React SPA Demo Client# React OIDC Demo (MrWhoOidc)



This is a sample React Single-Page Application (SPA) demonstrating integration with MrWhoOidc as an OpenID Connect Provider. It showcases a **public client** implementation using Authorization Code flow with PKCE in the browser.A minimal React + Vite + TypeScript client that authenticates against the MrWho OIDC server using oauth4webapi with PAR and front-channel logout.



## Technology StackFeatures

- PAR (Pushed Authorization Requests)

- **React 18**: Modern React with TypeScript- PKCE (S256)

- **Vite**: Build tool and dev server- Front-channel logout with id_token_hint

- **Authentication**: oauth4webapi (standards-compliant OIDC library)- Displays ID Token claims and stored tokens

- **Client Type**: Public (no client secret, browser-based)- TailwindCSS modern styling

- **OIDC Flows**: Authorization Code with PKCE (required for public clients)

Quick start

## Prerequisites1. cd Examples/ReactOidcClient

2. npm install

### Option 1 - Docker Compose (Recommended)3. npm run dev



- Docker Desktop or Docker Engine with Docker Compose V2Config

- GitCreate `.env` (optional):

```

### Option 2 - Local DevelopmentVITE_OIDC_AUTHORITY=https://mrwho.onrender.com

VITE_OIDC_CLIENT_ID=react-demo

- Node.js 20 or laterVITE_REDIRECT_URI=http://localhost:5173/callback

- npm or yarnVITE_POST_LOGOUT_REDIRECT_URI=http://localhost:5173/

- Docker (for running MrWhoOidc)```

- Git

Identity Provider

## Quick Start with Docker Compose- The demo targets https://mrwho.onrender.com by default. Ensure a public client with `client_id` matching VITE_OIDC_CLIENT_ID exists and allows PAR + `redirect_uri`.



This is the fastest way to see the demo in action.Notes

- Tokens and claims are stored in sessionStorage for demo purposes only.

### 1. Clone the Repository- For production, add state/nonce and replay protection storage, and consider silent token refresh.


```bash
git clone https://github.com/yourusername/MrWhoOidc.git
cd MrWhoOidc/MrWho/demos/react-client
```

### 2. Start MrWhoOidc and Demo Client

```bash
# Start both the OIDC provider and demo client
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d

# Check logs
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml logs -f react-demo
```

### 3. Register the Client

1. Open the Admin UI at <https://localhost:8443/admin>
2. Navigate to **Clients** → **Create Client**
3. Fill in the form:
   - **Client ID**: `react-spa-demo`
   - **Client Name**: `React SPA Demo`
   - **Client Type**: `Public` (SPAs cannot keep secrets)
   - **Grant Types**: `authorization_code`
   - **Redirect URIs**: `https://localhost:5173/callback`
   - **Post Logout Redirect URIs**: `https://localhost:5173/`
   - **Scopes**: `openid`, `profile`, `email`
   - **Require PKCE**: ✅ **Enabled** (required for public clients)
4. Save the client (no secret is generated for public clients)

### 4. Configure the Client

Create a `.env` file in the `react-client` directory:

```bash
VITE_OIDC_AUTHORITY=https://localhost:8443
VITE_OIDC_CLIENT_ID=react-spa-demo
VITE_OIDC_SCOPE=openid profile email
VITE_REDIRECT_URI=https://localhost:5173/callback
VITE_POST_LOGOUT_REDIRECT_URI=https://localhost:5173/
```

**Important**: Vite bakes environment variables into the static bundle at build time. Rebuild the Docker image after changing `.env`:

```bash
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml build react-demo
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d react-demo
```

### 5. Test the Application

1. Navigate to <https://localhost:5173>
2. Click **Login**
3. You'll be redirected to MrWhoOidc login page
4. Enter credentials (default: `admin@example.com` / `Admin123!`)
5. After successful authentication, you'll see user info
6. Test **Logout** to verify logout flow

## Local Development (Without Docker)

This approach lets you run the demo with hot reload for rapid development.

### 1. Start MrWhoOidc

```bash
cd MrWhoOidc/MrWho
docker compose up -d
```

### 2. Install Dependencies

```bash
cd demos/react-client
npm install
```

### 3. Configure the Demo

Create a `.env.local` file (overrides `.env`):

```bash
VITE_OIDC_AUTHORITY=https://localhost:8443
VITE_OIDC_CLIENT_ID=react-spa-demo
VITE_OIDC_SCOPE=openid profile email
VITE_REDIRECT_URI=https://localhost:5173/callback
VITE_POST_LOGOUT_REDIRECT_URI=https://localhost:5173/
```

### 4. Register the Client

Follow step 3 from the Docker Compose guide above.

### 5. Run the Development Server

```bash
npm run dev
```

The app will be available at <https://localhost:5173>

Vite provides hot module replacement (HMR) for instant feedback during development.

### 6. Build for Production

```bash
npm run build
npm run preview  # Preview production build locally
```

## Configuration Reference

The demo uses Vite environment variables (must start with `VITE_`):

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `VITE_OIDC_AUTHORITY` | `https://localhost:8443` | OIDC provider base URL |
| `VITE_OIDC_CLIENT_ID` | `react-spa-demo` | Client identifier |
| `VITE_OIDC_SCOPE` | `openid profile email` | Requested scopes (space-separated) |
| `VITE_REDIRECT_URI` | `https://localhost:5173/callback` | Callback URI after login |
| `VITE_POST_LOGOUT_REDIRECT_URI` | `https://localhost:5173/` | Redirect URI after logout |

**Important**: Environment variables are embedded at build time. Changes require rebuild.

### Accessing Variables in Code

```typescript
// src/oidc/config.ts
export const oidcConfig = {
  authority: import.meta.env.VITE_OIDC_AUTHORITY,
  clientId: import.meta.env.VITE_OIDC_CLIENT_ID,
  scope: import.meta.env.VITE_OIDC_SCOPE,
  redirectUri: import.meta.env.VITE_REDIRECT_URI,
  postLogoutRedirectUri: import.meta.env.VITE_POST_LOGOUT_REDIRECT_URI,
};
```

## Expected Behavior

### After Successful Login

You should see:

- **User Info**: Name, email, subject (from ID token)
- **Token Info**: Token expiration time
- **User Actions**: Logout button

### Authentication Flow (Browser-Based)

1. Click **Login** → Initiates OIDC flow
2. Generate PKCE challenge (code_verifier and code_challenge)
3. Redirect to MrWhoOidc `/authorize` endpoint with:
   - `response_type=code`
   - `code_challenge` and `code_challenge_method=S256`
   - `redirect_uri`, `scope`, `state`, `nonce`
4. User authenticates at MrWhoOidc
5. Redirect back to `/callback` with authorization code
6. Exchange code for tokens using PKCE verifier
7. Store tokens in session storage (or local storage)
8. Display user info

### Logout Flow

1. Click **Logout** → Initiates logout
2. Clear tokens from browser storage
3. Redirect to MrWhoOidc `/logout` endpoint with `id_token_hint` and `post_logout_redirect_uri`
4. MrWhoOidc clears session
5. Redirect back to app homepage

### Security Considerations

- **No Client Secret**: Public clients cannot securely store secrets
- **PKCE Required**: Protects against authorization code interception
- **Short Token Lifetime**: Tokens typically expire in 1 hour
- **State/Nonce**: Protects against CSRF and replay attacks
- **Session Storage**: Tokens stored in browser (cleared on tab close)

## Troubleshooting

### "Invalid Redirect URI" Error

**Cause**: Redirect URI not registered or mismatch.

**Solution**:

- Verify `https://localhost:5173/callback` is in client's Redirect URIs
- Check for typos (trailing slashes, http vs https)
- Ensure port matches (5173 is Vite default)

### "PKCE Required" Error

**Cause**: Client not configured to require PKCE.

**Solution**:

- In Admin UI, edit client
- Ensure **Require PKCE** is enabled
- Save and retry login

### "Unauthorized Client" Error

**Cause**: Client not registered or misconfigured.

**Solution**:

- Verify client exists in Admin UI
- Check `ClientId` matches exactly
- Ensure client type is **Public**
- Verify grant types include `authorization_code`

### SSL Certificate Errors

**Cause**: MrWhoOidc uses self-signed certificate.

**Solution**:

- Trust the certificate in browser (proceed past warning)
- Or configure MrWhoOidc with valid SSL certificate

### CORS Errors

**Cause**: Browser blocks requests to different origin.

**Solution**:

- MrWhoOidc should allow CORS for `https://localhost:5173`
- Check browser console for specific CORS error
- Verify OIDC endpoints support CORS

### Environment Variables Not Applied

**Cause**: Vite requires rebuild after env var changes.

**Solution**:

```bash
# Local development
npm run build

# Docker
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml build react-demo
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d react-demo
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

## Code Walkthrough

### OIDC Configuration (src/oidc/config.ts)

```typescript
export const oidcConfig = {
  authority: import.meta.env.VITE_OIDC_AUTHORITY || 'https://localhost:8443',
  clientId: import.meta.env.VITE_OIDC_CLIENT_ID || 'react-spa-demo',
  scope: import.meta.env.VITE_OIDC_SCOPE || 'openid profile email',
  redirectUri: import.meta.env.VITE_REDIRECT_URI || 'https://localhost:5173/callback',
  postLogoutRedirectUri: import.meta.env.VITE_POST_LOGOUT_REDIRECT_URI || 'https://localhost:5173/',
};
```

### Authentication Service (src/oidc/authService.ts)

Handles OIDC flows using oauth4webapi:

- `login()`: Initiates authorization code flow with PKCE
- `handleCallback()`: Exchanges code for tokens
- `logout()`: Clears tokens and redirects to logout endpoint
- `getUser()`: Decodes ID token to get user info
- `isAuthenticated()`: Checks if valid tokens exist

### Protected Route (src/components/ProtectedRoute.tsx)

Wraps components requiring authentication:

```typescript
export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
}
```

## Next Steps

- **Explore Admin UI**: Manage clients, users, scopes at <https://localhost:8443/admin>
- **Read Documentation**: See [MrWhoOidc docs](../../docs/) for advanced configuration
- **Try Other Demos**: Check out .NET MVC and Go client demos
- **Deploy to Production**: Review [deployment guide](../../docs/deployment-guide.md) for SPA deployment patterns

## Support

- **Issues**: <https://github.com/yourusername/MrWhoOidc/issues>
- **Documentation**: <https://github.com/yourusername/MrWhoOidc/tree/main/MrWho/docs>
