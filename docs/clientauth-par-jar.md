# MrWho ClientAuth: PAR & JAR Support

This guide shows how to enable Pushed Authorization Requests (PAR) and JWT Secured Authorization Requests (JAR) in client apps using the `MrWho.ClientAuth` NuGet package.

Audience: Blazor Server, Razor Pages, and ASP.NET Core apps authenticating against MrWho Identity Server (OpenIddict).

---

Contents
- When to use PAR/JAR
- Quick start
- App settings
- Advanced configuration
- Server (MrWho) requirements
- Troubleshooting

---

When to use PAR / JAR
- PAR solves long URL limits and hides sensitive request parameters by pushing them via back-channel first, returning a `request_uri`.
- JAR signs request parameters into a JWT (`request=`) to prevent tampering. Best with asymmetric keys. Combine with PAR for best reliability.

Quick start
1) Register ClientAuth

```csharp
// Program.cs / Startup
using MrWho.ClientAuth;
using MrWho.ClientAuth.Par;
using MrWho.ClientAuth.Jar;

var builder = WebApplication.CreateBuilder(args);

// (A) Basic ClientAuth with PAR auto-push and optional JAR
builder.Services
    .AddMrWhoParClient(builder.Configuration) // builds {authority}/connect/par & /connect/authorize
    .AddMrWhoJarSigner(o =>
    {
        // Choose either HS256 or RS256 signing
        // HS256 (dev): use a long client secret (>=32 bytes)
        o.Algorithm = Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256;
        o.ClientSecret = builder.Configuration["Authentication:ClientSecret"]; // confidential client
        // or RS256 (recommended for prod):
        // o.Algorithm = Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256;
        // o.RsaCertificate = LoadYourCert();
    });

builder.Services.AddMrWhoAuthentication(opt =>
{
    opt.Authority = builder.Configuration["Authentication:Authority"]!;
    opt.ClientId = builder.Configuration["Authentication:ClientId"]!;
    opt.ClientSecret = builder.Configuration["Authentication:ClientSecret"]; // confidential
    opt.UsePkce = true;
    opt.AutoParPush = true;  // enable PAR integration
    opt.EnableJar = true;    // enable JAR (used when PAR not used or as part of PAR payload)
    opt.JarOnlyWhenLarge = true; // only add JAR when URL would be large; set false to always sign
});
```

2) Map back-channel logout (optional)
```csharp
app.MapMrWhoBackChannelLogoutEndpoint();
```

App settings
```json
{
  "Authentication": {
    "Authority": "https://localhost:7113",
    "ClientId": "my_web_client",
    "ClientSecret": "<if confidential>",
    "UsePar": true,
    "UseJar": true,
    "JarOnlyWhenLarge": true
  },
  "Par": {
    "TimeoutSeconds": 15,
    "AutoPushQueryLengthThreshold": 1400,
    "FallbackWhenDisabled": true,
    "AutoJar": true
  }
}
```

Advanced configuration
- PAR
  - `AddMrWhoParClient(authority)` automatically sets `ParEndpoint={authority}/connect/par` and `AuthorizeEndpoint={authority}/connect/authorize`.
  - `ParClientOptions.AutoPushQueryLengthThreshold`: auto-push when the built URL would exceed threshold.
  - `AuthorizationRequest.UseBasicAuth`: default true; uses client_secret_basic if `ClientSecret` is set.
- JAR
  - `AddMrWhoJarSigner(options)`: choose HS256 (dev) or RS256 (prod). For HS256, the secret must be >= 32 bytes.
  - Claims included: iss, aud, client_id, redirect_uri, response_type, scope, state, iat, nbf, exp (+ PKCE when provided, nonce when available).
  - With PAR enabled, `request` is sent in the PAR form automatically.
- JARM (response_mode=jwt)
  - ClientAuth can request JARM (`MrWhoClientAuthOptions.EnableJarm = true`), but Microsoft’s OIDC handler does not natively parse JARM. Leave off unless you built custom handlers.

Server requirements (MrWho Identity Server)
- Client registration:
  - redirect_uris: include your app’s `https://{host}/signin-oidc`.
  - grant_types: authorization_code; scopes: openid profile email roles and your APIs.
  - For PAR: enable `/connect/par` and optionally set ParMode=Required per client.
  - For JAR: allow/require request objects; configure allowed algs (HS256/RS256). For RS256 register the client public key (JWKS) or thumbprint.
- Discovery should advertise `pushed_authorization_request_endpoint` and `request_parameter_supported`.

How it works (under the hood)
- During `OnRedirectToIdentityProvider`, the package:
  1. Normalizes authorize URL.
  2. If PAR is enabled, pushes the request (including JAR if a signer is registered) and switches to `request_uri`.
  3. If PAR is not used or fails (and fallback is allowed), optionally adds JAR to the authorize request.
  4. Keeps `state` and optional `response_mode` intact.

Troubleshooting
- 404 at /signin-oidc: ensure you didn’t map the callback route yourself; let the OIDC middleware handle it. Redirect URIs must match.
- `invalid_request` from PAR: check client supports PAR or disable `FallbackWhenDisabled` to force failure.
- JAR validation errors: verify signing algorithm/keys and aud/iss values expected by the server.
- Long URL before PAR kicks in: reduce `JarOnlyWhenLarge` or set `AutoPushQueryLengthThreshold` smaller, or force PAR by putting `use_par=1` into `AuthorizationRequest.Extra` if you’re using the low-level PAR APIs.

Examples
- Force PAR for specific challenges only: set an authentication property `use_par=1` and read it in your app’s OIDC redirect event to call the lower-level `IPushedAuthorizationService` directly.

Security notes
- Prefer RS256 JAR in production. Keep private keys secure and rotate regularly.
- Keep PAR/JAR feature flags configurable per environment.

---

Changelog
- v1.2: Added PAR client, JAR signer, and OIDC integration hooks with fallbacks.
