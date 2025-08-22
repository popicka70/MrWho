MrWho.ClientAuth
=================

A lightweight client-side configuration package to connect ASP.NET Core apps to the MrWho OpenID Connect identity server.

Quick start
-----------

1) Add the package reference.

Program.cs:
```csharp
builder.Services.AddMrWhoAuthentication(options =>
{
    options.Authority = "https://localhost:7113"; // public URL of MrWho
    options.ClientId = "my_app_client";
    options.ClientSecret = "optional-secret"; // for confidential clients
    // add API scopes if needed
    options.Scopes.Add("api.read");
});

builder.Services.AddAuthorization();
```

2) Map convenience login/logout endpoints (optional):
```csharp
app.MapMrWhoLoginEndpoint();
app.MapMrWhoLogoutEndpoints();
app.MapMrWhoBackChannelLogoutEndpoint();
```

3) Protect pages/controllers with `[Authorize]`.

Machine-to-Machine (client_credentials) helpers
----------------------------------------------
Add an HttpClient that transparently acquires and caches a client_credentials token:
```csharp
builder.Services.AddMrWhoClientCredentialsApi(
    name: "DemoApiM2M",
    baseAddress: new Uri("https://localhost:7162"),
    configure: opt =>
    {
        opt.Authority = "https://localhost:7113";
        opt.ClientId = "mrwho_demo_api_client";
        opt.ClientSecret = "DemoApiClientSecret2025!";
        opt.Scopes = new[] { "api.read" }; // optional
        opt.AcceptAnyServerCertificate = builder.Environment.IsDevelopment();
    });
```
Usage:
```csharp
var client = httpClientFactory.CreateClient("DemoApiM2M");
var resp = await client.GetAsync("WeatherForecast");
```

Delegated user access token forwarding
--------------------------------------
Forward the signed-in user's access token to an API:
```csharp
builder.Services.AddMrWhoUserAccessTokenApi(
    name: "DemoApiUser",
    baseAddress: new Uri("https://localhost:7162"));
```
Usage in page/controller:
```csharp
var api = httpClientFactory.CreateClient("DemoApiUser");
var resp = await api.GetAsync("WeatherForecast");
```

Typed client variants are also available:
```csharp
builder.Services.AddMrWhoClientCredentialsApi<MyApiClient>(new Uri("https://localhost:7162"), opt => { /* ... */ });
builder.Services.AddMrWhoUserAccessTokenApi<MyUserApiClient>(new Uri("https://localhost:7162"));
```

Notes and defaults
------------------
- Cookie + OIDC scheme naming isolated per ClientId.
- Saves tokens by default (access/id/refresh) when supported.
- Default scopes: openid, profile, email, roles, offline_access. Add api.read/api.write explicitly.
- Discovery path always: `/.well-known/openid-configuration`.
- M2M provider caches token until ~30s before expiry (configurable via RefreshSkew).
- Optional `AcceptAnyServerCertificate` for dev self-signed certs.

Security considerations
-----------------------
- Never enable `AcceptAnyServerCertificate` outside development.
- Store client secrets securely (user-secrets, KeyVault, environment). Do not commit to source control.
- Limit scopes to the minimum required (principle of least privilege).

Back-channel logout
-------------------
Map `app.MapMrWhoBackChannelLogoutEndpoint();` in apps that must honor session revocation.

License: MIT
