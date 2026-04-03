# MrWhoOidc Razor Client Demo

This sample shows how to build a confidential interactive web client against MrWhoOidc using ASP.NET Core Razor Pages and the `MrWhoOidc.Client` package.

## What It Demonstrates

- Authorization Code + PKCE
- local cookie sign-in
- discovery + JWKS bootstrap through the client package
- RP-initiated logout
- on-behalf-of access to a downstream API

## Prerequisites

- .NET 10 SDK
- a running MrWhoOidc issuer
- a registered confidential client with redirect URI support

For the easiest local issuer, run the root-level compose stack from this repository first.

## Run the Demo

```bash
cd demos/dotnet-mvc-client
dotnet run
```

Then open `https://localhost:5003`.

## Default Local Assumptions

The demo is typically pointed at the seeded local tenant:

- issuer: `https://localhost:8443/t/default`
- discovery: `https://localhost:8443/t/default/.well-known/openid-configuration`
- redirect URI: `https://localhost:5003/signin-oidc`
- post-logout redirect URI: `https://localhost:5003/signout-callback-oidc`

## How It Works

- `AddMrWhoOidcClient` registers discovery, token, authorization, logout, and JWKS helpers.
- the login page builds an authorization request with PKCE
- the callback page exchanges the code and signs the user into a local cookie
- the secure page performs an on-behalf-of exchange before calling the downstream API

## When To Use This Sample

Use this demo when you want a server-rendered .NET reference for:

- confidential-client login
- PKCE on interactive web apps
- logout handling
- delegated downstream API access

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

- **Explore Admin UI**: Manage clients, users, scopes at https://localhost:8443/admin/clients
- **Read Documentation**: See [MrWhoOidc docs](../../docs/) for advanced configuration
- **Try Other Demos**: Check out React SPA and Go client demos
- **Deploy to Production**: Review [deployment guide](../../docs/deployment-guide.md)

## Support

- **Issues**: https://github.com/yourusername/MrWhoOidc/issues
- **Documentation**: https://github.com/yourusername/MrWhoOidc/tree/main/MrWho/docs
