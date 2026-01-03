# .NET MVC Demo Client# MrWhoOidc Razor Client Example



This is a sample ASP.NET Core MVC application demonstrating integration with MrWhoOidc as an OpenID Connect Provider. It showcases a **confidential client** implementation using Authorization Code flow with PKCE.This Razor Pages sample shows how to authenticate an interactive web application against `MrWhoOidc.WebAuth` using the `MrWhoOidc.Client` library.



## Technology Stack## Prerequisites



- **.NET 9.0**: ASP.NET Core with Razor Pages- .NET 9 SDK (preview)

- **Authentication**: Microsoft.AspNetCore.Authentication.OpenIdConnect- A running instance of `MrWhoOidc.WebAuth` exposed at `https://localhost:7208`. The Aspire host (`MrWhoOidc.AppHost`) starts one for local development.

- **Client Type**: Confidential (requires client secret)- The `mrwho-admin` client registration seeded by `MrWhoOidc.Auth` with redirect URI `https://localhost:5003/signin-oidc`.

- **OIDC Flows**: Authorization Code with PKCE, token refresh, logout

## Running the sample

## Prerequisites

1. Start the platform locally (for example via `dotnet run --project MrWhoOidc.AppHost`).

### Option 1: Docker Compose (Recommended)2. Launch the Razor client:



- Docker Desktop or Docker Engine with Docker Compose V2    ```powershell

- Git    dotnet run --project Examples/MrWhoOidc.RazorClient/MrWhoOidc.RazorClient.csproj

    ```

### Option 2: Local Development

3. Navigate to `https://localhost:5003` and choose **Sign in with MrWhoOidc**. You should be redirected to the MrWhoOidc login page and, after authenticating, back to the sample where issued tokens and claims are displayed.

- .NET 9 SDK4. Visit the **Secure** page to trigger an on-behalf-of exchange. The page uses a typed `HttpClient` with `AddMrWhoOnBehalfOfTokenHandler` to call the sample API (`MrWhoOidc.TestApi`) and renders the returned subject/actor data.

- Docker (for running MrWhoOidc)

- Git## How it works



## Quick Start with Docker Compose- `MrWhoOidc.Client` is registered via `AddMrWhoOidcClient`, exposing the discovery, authorization, and token helper services.

- The `/Auth/Login` page uses `IMrWhoAuthorizationManager` to produce an authorization request with PKCE and caches the verifier in-memory.

This is the fastest way to see the demo in action.- `/Auth/Callback` exchanges the authorization code through `IMrWhoTokenClient`, validates the nonce, and signs the user into a local cookie.

- `/Auth/Logout` lets the user choose between signing out only of this Razor app or federating the sign-out with the issuer using `IMrWhoLogoutManager` from the client package.

### 1. Clone the Repository- The home page reads cached discovery metadata and displays the stored tokens/claims to prove the flow succeeded.

- The on-behalf-of demo page injects `OboApiClient`, which relies on the `IMrWhoOnBehalfOfManager` helper to exchange the signed-in user's access token for one targeted at the downstream API. The resulting access token is attached automatically to the outgoing HTTP request.

```bash

git clone https://github.com/yourusername/MrWhoOidc.gitAdjust the configuration in `appsettings.json` if you register a different client or change the issuer URL.

cd MrWhoOidc/MrWho/demos/dotnet-mvc-client
```

### 2. Start MrWhoOidc and Demo Client

```bash
# Start both the OIDC provider and demo client
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml up -d

# Check logs
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml logs -f dotnet-mvc-demo
```

### 3. Register the Client

1. Open the Admin UI: https://localhost:8443/admin
2. Navigate to **Clients** → **Create Client**
3. Fill in the form:
   - **Client ID**: `dotnet-mvc-demo`
   - **Client Name**: `.NET MVC Demo`
   - **Client Type**: `Confidential`
   - **Grant Types**: `authorization_code`, `refresh_token`
   - **Redirect URIs**: `https://localhost:5001/signin-oidc`
   - **Post Logout Redirect URIs**: `https://localhost:5001/signout-callback-oidc`
   - **Scopes**: `openid`, `profile`, `email`
4. Save the client and **copy the generated client secret**

### 4. Configure the Client Secret

Create a `.env` file in the `dotnet-mvc-client` directory:

```bash
MrWhoOidc__ClientSecret=your-secret-from-admin-ui
```

Restart the demo client:

```bash
docker compose -f ../docker-compose.yml -f docker-compose.demo.yml restart dotnet-mvc-demo
```

### 5. Test the Application

1. Navigate to: https://localhost:5001
2. Click **Login**
3. You'll be redirected to MrWhoOidc login page
4. Enter credentials (default: `admin@example.com` / `Admin123!`)
5. After successful authentication, you'll see user claims
6. Test **Logout** to verify logout flow

## Local Development (Without Docker)

This approach lets you run the demo on your local machine and debug with Visual Studio or VS Code.

### 1. Start MrWhoOidc

```bash
cd MrWhoOidc/MrWho
docker compose up -d
```

### 2. Configure the Demo

Copy `appsettings.json` to `appsettings.Development.json` and update:

```json
{
  "MrWhoOidc": {
    "Issuer": "https://localhost:8443",
    "ClientId": "dotnet-mvc-demo",
    "ClientSecret": "your-secret-from-admin-ui",
    "Scopes": "openid profile email",
    "RedirectUri": "https://localhost:5001/signin-oidc",
    "PostLogoutRedirectUri": "https://localhost:5001/signout-callback-oidc"
  }
}
```

### 3. Register the Client

Follow step 3 from the Docker Compose guide above.

### 4. Run the Application

```bash
dotnet run
```

Or open `MrWhoOidc.RazorClient.csproj` in Visual Studio and press F5.

### 5. Test the Application

Navigate to: https://localhost:5001

## Configuration Reference

The demo supports environment variables (Docker) or appsettings.json (local):

| Environment Variable | appsettings.json Path | Default | Description |
|---------------------|----------------------|---------|-------------|
| `MrWhoOidc__Issuer` | `MrWhoOidc:Issuer` | `https://localhost:8443` | OIDC provider base URL |
| `MrWhoOidc__ClientId` | `MrWhoOidc:ClientId` | `dotnet-mvc-demo` | Client identifier |
| `MrWhoOidc__ClientSecret` | `MrWhoOidc:ClientSecret` | *(required)* | Client secret from Admin UI |
| `MrWhoOidc__Scopes` | `MrWhoOidc:Scopes` | `openid profile email` | Requested scopes |
| `MrWhoOidc__RedirectUri` | `MrWhoOidc:RedirectUri` | `https://localhost:5001/signin-oidc` | Callback URI |
| `MrWhoOidc__PostLogoutRedirectUri` | `MrWhoOidc:PostLogoutRedirectUri` | `https://localhost:5001/signout-callback-oidc` | Post-logout URI |

## Expected Behavior

### After Successful Login

You should see a page displaying:

- **User Claims**: ID token claims (sub, name, email, etc.)
- **Access Token**: Masked token (first/last 10 chars)
- **Refresh Token**: Masked token (if granted)
- **Expires At**: Token expiration timestamp

### Authentication Flow

1. Click **Login** → Redirects to MrWhoOidc `/authorize` endpoint
2. User enters credentials → MrWhoOidc validates
3. User grants consent (if needed)
4. Redirect back to `/signin-oidc` with authorization code
5. Demo exchanges code for tokens (ID token, access token, refresh token)
6. Session established with cookie

### Logout Flow

1. Click **Logout** → Demo initiates logout
2. Redirect to MrWhoOidc `/logout` endpoint
3. MrWhoOidc clears session
4. Redirect back to `/signout-callback-oidc`
5. Demo clears local session and cookie

## Troubleshooting

### "Unauthorized" Error

**Cause**: Client not registered or client secret mismatch.

**Solution**:
- Verify client is registered in Admin UI
- Check `ClientId` matches registration
- Verify `ClientSecret` is correct
- Check redirect URIs match exactly (including protocol and port)

### "Invalid Redirect URI" Error

**Cause**: Redirect URI not registered in Admin UI.

**Solution**:
- Ensure `https://localhost:5001/signin-oidc` is listed in client's Redirect URIs
- Check for typos (trailing slashes, http vs https)

### SSL Certificate Errors

**Cause**: MrWhoOidc uses self-signed certificate by default.

**Solution**:
- Trust the development certificate: `dotnet dev-certs https --trust`
- Or add `https://localhost:8443` to browser trusted sites

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

### Token Refresh Issues

**Cause**: `refresh_token` grant not enabled for client.

**Solution**:
- In Admin UI, edit client and ensure `refresh_token` is in **Grant Types**
- Save and restart demo

## Code Walkthrough

### Program.cs Configuration

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = configuration["MrWhoOidc:Issuer"];
    options.ClientId = configuration["MrWhoOidc:ClientId"];
    options.ClientSecret = configuration["MrWhoOidc:ClientSecret"];
    options.ResponseType = "code"; // Authorization Code flow
    options.UsePkce = true; // Enable PKCE
    options.SaveTokens = true; // Save tokens to authentication ticket
    options.GetClaimsFromUserInfoEndpoint = true;
    
    // Request scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("offline_access"); // For refresh token
});
```

### Home/Index.cshtml

Displays authenticated user information:

```csharp
@if (User.Identity?.IsAuthenticated == true)
{
    <h2>Welcome, @User.Identity.Name!</h2>
    
    <h3>User Claims</h3>
    <ul>
        @foreach (var claim in User.Claims)
        {
            <li><strong>@claim.Type:</strong> @claim.Value</li>
        }
    </ul>
    
    <a asp-controller="Account" asp-action="Logout">Logout</a>
}
else
{
    <a asp-controller="Account" asp-action="Login">Login</a>
}
```

## Next Steps

- **Explore Admin UI**: Manage clients, users, scopes at https://localhost:8443/admin
- **Read Documentation**: See [MrWhoOidc docs](../../docs/) for advanced configuration
- **Try Other Demos**: Check out React SPA and Go client demos
- **Deploy to Production**: Review [deployment guide](../../docs/deployment-guide.md)

## Support

- **Issues**: https://github.com/yourusername/MrWhoOidc/issues
- **Documentation**: https://github.com/yourusername/MrWhoOidc/tree/main/MrWho/docs
