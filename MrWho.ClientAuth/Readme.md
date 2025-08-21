MrWho.ClientAuth
=================

A lightweight client-side configuration package to connect ASP.NET Core apps to the MrWho OpenID Connect identity server.

Quick start
-----------

1) Add the package reference (this project builds into a NuGet):

- In your app's Program.cs:

```csharp
builder.Services.AddMrWhoAuthentication(options =>
{
    options.Authority = "https://localhost:7113"; // public URL of MrWho
    options.ClientId = "my_app_client";
    options.ClientSecret = "optional-secret"; // for confidential clients
    // optionally tweak scopes, metadata, etc.
});

builder.Services.AddAuthorization();
```

2) Use the standard [Authorize] attributes and the default cookie scheme created by the package.

3) (Optional) Map convenience login/logout endpoints:

```csharp
app.MapMrWhoLoginEndpoint();      // GET /login?returnUrl=/protected
app.MapMrWhoLogoutEndpoints();    // GET/POST /logout?returnUrl=/
app.MapMrWhoBackChannelLogoutEndpoint(); // POST /signout-backchannel
```

Or call Challenge/SignOut manually:

```csharp
// Login
app.MapGet("/login-direct", ctx => ctx.ChallengeAsync());
// Logout
app.MapPost("/logout-direct", ctx => ctx.SignOutAsync());
```

Notes and defaults
------------------
- Uses cookie authentication for local session storage and OpenIdConnect challenge.
- Saves tokens to the auth session by default.
- Requests recommended scopes: openid, profile, email, roles, offline_access, api.read, api.write.
- Always uses the correct discovery endpoint path: /.well-known/openid-configuration
- Supports explicit MetadataAddress override for containerized deployments.
- Supports trusting self-signed certificates for development.
- Provides optional mapped endpoints: /login, /logout (GET+POST) and /signout-backchannel.
