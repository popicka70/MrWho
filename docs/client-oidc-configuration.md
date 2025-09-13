# MrWho Client OIDC Configuration Guide

This document explains how to configure an ASP.NET Core (Razor Pages, MVC, Blazor Server) application using the `MrWho.ClientAuth` NuGet package with optional PAR + JAR support.

---
## 1. Package Reference
Add the client package (already in solution projects; for external apps add NuGet):
```
<PackageReference Include="MrWho.ClientAuth" Version="*" />
```

---
## 2. Basic Authentication Setup
In `Program.cs` (server-side Blazor or Razor Pages app):
```csharp
builder.Services.AddMrWhoAuthentication(o =>
{
    o.ClientId = "your_client_id";
    o.Authority = "https://localhost:7113"; // MrWho Identity base URL
    o.ClientSecret = "optional_if_confidential"; // public clients omit
    // o.Scopes.Add("api.read"); // add API scopes as needed
});
```
The extension registers:
- Cookie scheme: `MrWho.{ClientId}.Cookies`
- OIDC scheme: `MrWho.{ClientId}.OIDC`
- Default challenge/sign-out = OIDC scheme

---
## 3. Optional Login/Logout Convenience Endpoints
Map helper endpoints (instead of manual `ChallengeAsync`/`SignOutAsync`):
```csharp
app.MapMrWhoLoginEndpoint();    // /login?returnUrl=/
app.MapMrWhoLogoutEndpoints();  // /logout
```
Back-channel logout (if enabled on server):
```csharp
app.MapMrWhoBackChannelLogoutEndpoint(); // /signout-backchannel
```

---
## 4. PAR (Pushed Authorization Requests)
Add PAR client services:
```csharp
using MrWho.ClientAuth.Par;

builder.Services.AddMrWhoParClient(o =>
{
    o.ParEndpoint = new Uri("https://localhost:7113/connect/par");
    // o.AuthorizeEndpoint optional (defaults to /connect/authorize)
    // o.AutoPushQueryLengthThreshold = 1400; // adjust or set 0 to disable auto
});
```
Usage (build authorize URL automatically deciding between direct vs PAR push):
```csharp
public class OidcLauncher
{
    private readonly IPushedAuthorizationService _par;
    public OidcLauncher(IPushedAuthorizationService par) => _par = par;

    public async Task<string> BuildAsync(string pkceChallenge)
    {
        var req = new AuthorizationRequest
        {
            ClientId = "your_client_id",
            RedirectUri = "https://localhost:5001/signin-oidc",
            Scope = "openid profile email",
            State = Guid.NewGuid().ToString("N"),
            CodeChallenge = pkceChallenge
        };
        var uri = await _par.BuildAuthorizeUrlAsync(req);
        return uri.ToString();
    }
}
```
Force PAR even if short query: add `use_par=1` to `Extra` or disable threshold.

Fallback: If server returns `PAR disabled` and `FallbackWhenDisabled=true` the service builds a classic front-channel URL.

---
## 5. JAR (JWT Secured Authorization Request) Signing
Register signer (HS256 example):
```csharp
using MrWho.ClientAuth.Jar;

builder.Services.AddMrWhoJarSigner(o =>
{
    o.Algorithm = SecurityAlgorithms.HmacSha256;
    o.ClientSecret = builder.Configuration["Oidc:ClientSecret"]; // >=32 bytes
    o.Issuer = "your_client_id"; // defaults to client_id if omitted
    o.Audience = "mrwho";        // server logical audience
});
```
RS256 with PEM key:
```csharp
builder.Services.AddMrWhoJarSigner(o =>
{
    o.Algorithm = SecurityAlgorithms.RsaSha256;
    o.RsaPrivateKeyPem = File.ReadAllText("keys/jar-signing.pem");
});
```
RS256 with certificate:
```csharp
var cert = new X509Certificate2("certs/jar_signing.pfx", "pfxPassword");
builder.Services.AddMrWhoJarSigner(o =>
{
    o.Algorithm = SecurityAlgorithms.RsaSha256;
    o.RsaCertificate = cert;
});
```
### Auto Integration with PAR Service
If both PAR and JAR services are registered:
- Building URL via `IPushedAuthorizationService` will automatically create a signed `request` object (JAR) when `AutoJar=true` (default) if none supplied.
- With PAR push: only `client_id` + `request_uri` appear in browser URL; original parameters & JAR stay back-channel.
- Without PAR push: JAR is still embedded (single `request` param) to reduce visible query parameters and enable integrity validation.

---
## 6. PKCE Helper (Example)
```csharp
public static (string Verifier, string Challenge) CreatePkce()
{
    using var rng = RandomNumberGenerator.Create();
    var bytes = new byte[32];
    rng.GetBytes(bytes);
    var verifier = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
    using var sha = SHA256.Create();
    var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(verifier));
    var challenge = Convert.ToBase64String(hash).TrimEnd('=').Replace('+','-').Replace('/','_');
    return (verifier, challenge);
}
```
Store PKCE verifier & state in temp data / session before redirect.

---
## 7. Blazor Server Considerations
- Place a login button that navigates to `/login` (or builds a PAR/JAR URL and uses `NavigationManager.NavigateTo(url, forceLoad:true)` to trigger external redirect).
- After callback (`/signin-oidc`), use `AuthenticationStateProvider` or `HttpContext` (for interactive server components) to access claims.

---
## 8. Logout Flows
Front-channel sign-out:
```csharp
await HttpContext.SignOutAsync(); // triggers OIDC end-session (default sign-out scheme)
```
Or navigate to `/logout` (mapped helper).
Back-channel logout: server posts to `/signout-backchannel`; local cookie cleared automatically.

---
## 9. Error Handling
`IPushedAuthorizationService.PushAsync` returns `(Result, Error)` tuple. Typical errors:
- `invalid_client` / unknown client
- `invalid_request` / PAR disabled (falls back if configured)
- `network_error` / transport failure
Throwing variant: `BuildAuthorizeUrlAsync` raises `InvalidOperationException` if push fails and no fallback.

---
## 10. Security Notes
- Do not log raw `request` JWT or client secrets.
- Ensure HS key length >= 32 bytes.
- Keep RS256 private keys outside repo; use environment or secret store.
- Always use PKCE for public clients.
- Prefer PAR + JAR when handling sensitive or large parameter sets.

---
## 11. Minimal End-to-End Flow (Summary)
1. User clicks Login.
2. App builds authorize URL (PAR push -> get `request_uri`).
3. Browser redirected to `/connect/authorize?client_id=...&request_uri=...`.
4. Server resolves stored parameters + validates JAR.
5. User authenticates / consents; authorization code issued.
6. OIDC middleware redeems code at `/connect/token`.
7. App receives tokens; user authenticated.

---
## 12. Troubleshooting
| Symptom | Cause | Fix |
|--------|-------|-----|
| Discovery fails | Wrong well-known path | Use `/.well-known/openid-configuration` |
| PAR push 400 (PAR disabled) | Client ParMode=Disabled | Enable PAR or allow fallback |
| `signature invalid` (JAR) | Wrong key/secret | Match algorithm & key with server config |
| HS256 rejected | Secret too short | Use >= 32 byte secret |
| URL too long | Large params w/out PAR | Enable PAR or lower threshold |

---
## 13. Example Combined Registration
```csharp
builder.Services
    .AddMrWhoAuthentication(o =>
    {
        o.ClientId = "demo_web";
        o.Authority = "https://localhost:7113";
        o.ClientSecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // if confidential
    })
    .Services
    .AddMrWhoJarSigner(o =>
    {
        o.Algorithm = SecurityAlgorithms.HmacSha256;
        o.ClientSecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    })
    .AddMrWhoParClient(o =>
    {
        o.ParEndpoint = new Uri("https://localhost:7113/connect/par");
        o.AutoPushQueryLengthThreshold = 800; // more aggressive
    });
```

---
## 14. References
- OpenID Connect Core
- OAuth 2.0 PAR (RFC 9126)
- JWT Secured Authorization Request (JAR)

---
**End of Guide**
