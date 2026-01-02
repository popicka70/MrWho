# OBO (On-Behalf-Of) Demo Implementation Plan

This document describes the plan for adding an OBO/Token Exchange demo to the MrWho demos. The demo will showcase RFC 8693 Token Exchange where a client application calls a protected API on behalf of a logged-in user.

## Overview

### Goal

Demonstrate the complete On-Behalf-Of (OBO) flow:

1. User logs into the **dotnet-mvc-demo** client
2. User clicks a button to call the **OBO Demo API**
3. The dotnet-mvc-demo performs token exchange at MrWhoOidc's `/token` endpoint
4. The OBO Demo API validates the exchanged token and returns information about:
   - The **subject** (the original user)
   - The **actor** (the client acting on behalf of the user)

### Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  User Browser   │──────│ dotnet-mvc-demo │──────│  MrWhoOidc IdP  │
│                 │      │  (Client App)   │      │  (Auth Server)  │
└─────────────────┘      └────────┬────────┘      └─────────────────┘
                                  │                        │
                                  │ Token Exchange         │
                                  │ (grant_type=           │
                                  │  urn:ietf:params:      │
                                  │  oauth:grant-type:     │
                                  │  token-exchange)       │
                                  │◄───────────────────────┤
                                  │                        │
                                  ▼                        
                         ┌─────────────────┐
                         │  obo-demo-api   │
                         │ (.NET 10 API)   │
                         └─────────────────┘
```

---

## Components to Create/Modify

### 1. New Component: OBO Demo API (`MrWho/demos/obo-demo-api/`)

A minimal .NET 10 Web API that:
- Validates JWT bearer tokens issued by MrWhoOidc
- Exposes a `/me` endpoint that returns subject and actor information
- Uses `MrWhoOidc.Client` for JWKS caching and token validation

#### Files to Create

| File | Purpose |
|------|---------|
| `obo-demo-api/obo-demo-api.csproj` | .NET 10 project file with `MrWhoOidc.Client` reference |
| `obo-demo-api/Program.cs` | Minimal API with JWT bearer authentication |
| `obo-demo-api/appsettings.json` | Configuration for issuer, audience |
| `obo-demo-api/appsettings.Development.json` | Development overrides |
| `obo-demo-api/Dockerfile` | Multi-stage Dockerfile for containerized deployment |
| `obo-demo-api/README.md` | Documentation |

#### API Design

```csharp
// GET /me - Returns information about the token subject and actor
app.MapGet("/me", (ClaimsPrincipal user) =>
{
    // Extract subject claims
    var subject = user.FindFirst("sub")?.Value;
    var name = user.FindFirst("name")?.Value;
    var email = user.FindFirst("email")?.Value;
    
    // Extract actor claim (populated by OBO)
    var actClaim = user.FindFirst("act")?.Value;
    string? actorClientId = null;
    if (!string.IsNullOrEmpty(actClaim))
    {
        // Parse {"sub": "dotnet-mvc-demo"} from act claim
        using var doc = JsonDocument.Parse(actClaim);
        actorClientId = doc.RootElement.GetProperty("sub").GetString();
    }
    
    return Results.Ok(new
    {
        message = "Called on behalf of user",
        subject,
        name,
        email,
        actor = actorClientId,
        audience = user.FindFirst("aud")?.Value,
        scopes = user.FindFirst("scope")?.Value?.Split(' '),
        issuedAt = user.FindFirst("iat")?.Value,
        expiresAt = user.FindFirst("exp")?.Value
    });
}).RequireAuthorization();
```

#### Configuration

```json
{
  "MrWhoOidc": {
    "Issuer": "https://mrwho.local:9443",
    "Audience": "obo-demo-api"
  }
}
```

---

### 2. OIDC Seed Manifest Updates (`MrWho/demos/oidc-seed-manifest.json`)

#### 2.1 Add API Client for OBO Demo API

This is the **first API-type client** in the demo seed manifest. It differs from interactive clients:
- No redirect URIs (machine-to-machine / API resource)
- Configured as a target audience for OBO
- No user-facing login flows

```json
{
  "clientId": "obo-demo-api",
  "clientName": "OBO Demo API",
  "realm": "admin",
  "requirePkce": false,
  "requireConsent": false,
  "allowedScopes": ["openid", "profile", "email", "api.read"],
  "clientSecretEnv": "OBO_DEMO_API_SECRET"
}
```

#### 2.2 Update dotnet-mvc-demo Client for OBO

The existing `dotnet-mvc-demo` client needs OBO policy configuration to allow it to perform token exchange:

```json
{
  "clientId": "dotnet-mvc-demo",
  "clientName": ".NET MVC Demo Client",
  "realm": "admin",
  "requirePkce": true,
  "requireConsent": false,
  "autoApprovalMode": "All",
  "allowedScopes": [
    "openid",
    "profile",
    "email",
    "offline_access",
    "api.read"
  ],
  "clientSecretEnv": "DOTNET_MVC_CLIENT_SECRET",
  "allowedLoginRedirectUris": [
    "https://localhost:5001/Auth/Callback",
    "http://localhost:5001/Auth/Callback",
    "http://localhost:5000/Auth/Callback"
  ],
  "allowedLogoutRedirectUris": [
    "https://localhost:5001/",
    "https://localhost:5001/Auth/Logout",
    "http://localhost:5001/",
    "http://localhost:5000/"
  ],
  "oboEnabled": true,
  "oboAllowedTargetAudiences": ["obo-demo-api"],
  "oboAllowedScopes": ["openid", "profile", "email", "api.read"],
  "oboMaxLifetimeMinutes": 15,
  "oboMaxDelegationDepth": 1
}
```

#### 2.3 Add Custom Scope Definition (if needed)

If `api.read` scope isn't already defined globally, add it to the scopes section:

```json
{
  "scopes": [
    {
      "name": "api.read",
      "displayName": "Read API Data",
      "description": "Allows reading data from demo APIs"
    }
  ]
}
```

---

### 3. Modify dotnet-mvc-demo Client

#### 3.1 Add OBO Configuration to `appsettings.json`

```json
{
  "MrWhoOidc": {
    "Issuer": "https://mrwho.local:9443",
    "ClientId": "dotnet-mvc-demo",
    "ClientSecret": "...",
    "Scopes": ["openid", "profile", "email", "offline_access", "api.read"],
    "UsePkce": true,
    "OnBehalfOf": {
      "obo-demo-api": {
        "Scope": "openid profile email api.read",
        "Audience": "obo-demo-api",
        "CacheLifetime": "00:05:00"
      }
    }
  },
  "OboApi": {
    "BaseAddress": "https://localhost:7200"
  }
}
```

#### 3.2 Add OBO API Client Service

Create `Services/OboApiClient.cs`:

```csharp
public sealed class OboApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<OboApiClient> _logger;

    public OboApiClient(HttpClient httpClient, ILogger<OboApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<OboApiResponse?> GetProfileAsync(CancellationToken ct = default)
    {
        using var response = await _httpClient.GetAsync("me", ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("OBO API call failed: {StatusCode}", response.StatusCode);
            return null;
        }
        return await response.Content.ReadFromJsonAsync<OboApiResponse>(ct);
    }

    public sealed record OboApiResponse(
        string? Message,
        string? Subject,
        string? Name,
        string? Email,
        string? Actor,
        string? Audience,
        IEnumerable<string>? Scopes,
        string? IssuedAt,
        string? ExpiresAt);
}
```

#### 3.3 Register HttpClient with OBO Handler in `Program.cs`

```csharp
builder.Services.AddHttpClient<OboApiClient>((sp, client) =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        var baseAddress = config["OboApi:BaseAddress"];
        if (Uri.TryCreate(baseAddress, UriKind.Absolute, out var uri))
        {
            client.BaseAddress = uri;
        }
    })
    .AddMrWhoOnBehalfOfTokenHandler("obo-demo-api", async (sp, ct) =>
    {
        var accessor = sp.GetRequiredService<IHttpContextAccessor>();
        var context = accessor.HttpContext;
        if (context is null) return null;
        return await context.GetTokenAsync("access_token");
    });
```

#### 3.4 Add UI Page for OBO Demo

Create `Pages/OboDemo.cshtml` and `Pages/OboDemo.cshtml.cs`:

**OboDemo.cshtml.cs:**
```csharp
[Authorize]
public class OboDemoModel : PageModel
{
    private readonly OboApiClient _oboApi;

    public OboDemoModel(OboApiClient oboApi) => _oboApi = oboApi;

    public OboApiClient.OboApiResponse? ApiResponse { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnPostCallApiAsync()
    {
        try
        {
            ApiResponse = await _oboApi.GetProfileAsync();
            if (ApiResponse is null)
                ErrorMessage = "API returned no response";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        return Page();
    }
}
```

**OboDemo.cshtml:**
```html
@page
@model OboDemoModel
@{
    ViewData["Title"] = "OBO Demo";
}

<h1>On-Behalf-Of Demo</h1>
<p>Click the button to call the OBO Demo API on your behalf.</p>

<form method="post" asp-page-handler="CallApi">
    <button type="submit" class="btn btn-primary">Call API On My Behalf</button>
</form>

@if (Model.ApiResponse is not null)
{
    <div class="card mt-4">
        <div class="card-header">API Response</div>
        <div class="card-body">
            <p><strong>Message:</strong> @Model.ApiResponse.Message</p>
            <p><strong>Subject (User):</strong> @Model.ApiResponse.Subject</p>
            <p><strong>Name:</strong> @Model.ApiResponse.Name</p>
            <p><strong>Actor (Client):</strong> @Model.ApiResponse.Actor</p>
            <p><strong>Audience:</strong> @Model.ApiResponse.Audience</p>
            <p><strong>Scopes:</strong> @string.Join(", ", Model.ApiResponse.Scopes ?? [])</p>
        </div>
    </div>
}

@if (Model.ErrorMessage is not null)
{
    <div class="alert alert-danger mt-4">@Model.ErrorMessage</div>
}
```

---

### 4. Docker Compose Updates (`MrWho/demos/docker-compose.yml`)

#### 4.1 Add OBO Demo API Service

```yaml
  # ============================================================================
  # OBO Demo API - Demonstrates On-Behalf-Of token validation
  # ============================================================================
  obo-demo-api:
    build:
      context: ../..
      dockerfile: MrWho/demos/obo-demo-api/Dockerfile
    container_name: obo-demo-api
    
    depends_on:
      mrwho-oidc:
        condition: service_healthy
    
    environment:
      ASPNETCORE_ENVIRONMENT: Development
      ASPNETCORE_URLS: https://+:7200;http://+:7199
      ASPNETCORE_HTTPS_PORT: 7200
      ASPNETCORE_Kestrel__Certificates__Default__Path: /https/aspnetapp.pfx
      ASPNETCORE_Kestrel__Certificates__Default__Password: ${CERT_PASSWORD:-changeit}
      MrWhoOidc__Issuer: https://mrwho.local:9443
      MrWhoOidc__Audience: obo-demo-api
      MrWhoOidc__RequireHttpsMetadata: "false"
      MrWhoOidc__DangerousAcceptAnyServerCertificateValidator: "true"
    
    extra_hosts:
      - "localhost:host-gateway"
      - "mrwho.local:host-gateway"
    
    volumes:
      - ../../MrWhoOidc/certs:/https:ro
    
    ports:
      - "7200:7200"
      - "7199:7199"
    
    healthcheck:
      test: ["CMD", "curl", "-f", "-k", "https://localhost:7200/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    
    restart: unless-stopped
    
    networks:
      - edge
```

#### 4.2 Update dotnet-mvc-demo Service

Add environment variables for OBO configuration:

```yaml
  dotnet-mvc-demo:
    # ... existing config ...
    environment:
      # ... existing vars ...
      
      # OBO Configuration
      MrWhoOidc__OnBehalfOf__obo-demo-api__Scope: "openid profile email api.read"
      MrWhoOidc__OnBehalfOf__obo-demo-api__Audience: "obo-demo-api"
      MrWhoOidc__OnBehalfOf__obo-demo-api__CacheLifetime: "00:05:00"
      OboApi__BaseAddress: "https://obo-demo-api:7200"
```

---

### 5. Seed Manifest Enhancement Considerations

#### 5.1 API Client vs Interactive Client

This is the first "API resource" style client in the demo manifest. Key differences:

| Aspect | Interactive Client | API Client |
|--------|-------------------|------------|
| Redirect URIs | Required | Not needed |
| PKCE | Usually enabled | Not applicable |
| User flows | Login/logout | None |
| Token usage | Issues tokens | Validates tokens |
| Consent | May require | N/A |

The seed manifest schema already supports this via empty `allowedLoginRedirectUris` / `allowedLogoutRedirectUris`.

#### 5.2 OBO Policy Fields Reference

From [ClientSeedDefinition](../MrWhoOidc/MrWhoOidc.Auth/Seeding/SeedManifest.cs):

| Field | Type | Purpose |
|-------|------|---------|
| `oboEnabled` | bool? | Enable/disable OBO for this client |
| `oboAllowedSourceAudiences` | string[] | Allowed `aud` values in subject tokens |
| `oboAllowedTargetAudiences` | string[] | Allowed target audiences for exchange |
| `oboAllowedScopes` | string[] | Allowed scopes in exchanged tokens |
| `oboAllowedCallers` | string[] | Which clients can exchange for this audience |
| `oboMaxDelegationDepth` | int? | Max delegation chain depth (default: 1) |
| `oboMaxLifetimeMinutes` | int? | Max lifetime of exchanged tokens |
| `oboDpopMode` | string? | DPoP bridging: "Deny", "RequireSameJkt", "AllowSameJktOnly" |

---

## Implementation Sequence

### Phase 1: Seed Manifest Updates
1. Add `api.read` scope definition (if not present)
2. Add `obo-demo-api` client definition
3. Update `dotnet-mvc-demo` client with OBO policy
4. Test seeding works correctly

### Phase 2: OBO Demo API
1. Create project structure
2. Implement minimal API with JWT bearer auth
3. Create Dockerfile
4. Test locally against running MrWhoOidc

### Phase 3: dotnet-mvc-demo Modifications
1. Add OBO configuration to appsettings
2. Create `OboApiClient` service
3. Register HttpClient with OBO handler
4. Create OBO demo page

### Phase 4: Docker Compose Integration
1. Add obo-demo-api service
2. Update dotnet-mvc-demo with OBO environment vars
3. Test full flow in containerized environment

### Phase 5: Documentation & Testing
1. Update demo README
2. Add E2E test scenario (optional)
3. Screenshots / demo script

---

## Complete Seed Manifest (Updated)

```json
{
  "version": 2,
  "licenses": [
    {
      "scope": "platform",
      "licenseTokenPath": "/seed/oidc-license.txt",
      "notes": "Demo license installed via seed manifest"
    }
  ],
  "scopes": [
    {
      "name": "api.read",
      "displayName": "Read API Data",
      "description": "Allows reading data from demo APIs"
    }
  ],
  "tenants": [
    {
      "slug": "default",
      "name": "Default Tenant",
      "description": "Demo tenant for MrWhoOidc demos",
      "realms": [
        { "name": "admin", "displayName": "Admin Realm" }
      ],
      "clients": [
        {
          "clientId": "dotnet-mvc-demo",
          "clientName": ".NET MVC Demo Client",
          "realm": "admin",
          "requirePkce": true,
          "requireConsent": false,
          "autoApprovalMode": "All",
          "allowedScopes": [
            "openid",
            "profile",
            "email",
            "offline_access",
            "api.read"
          ],
          "clientSecretEnv": "DOTNET_MVC_CLIENT_SECRET",
          "allowedLoginRedirectUris": [
            "https://localhost:5001/Auth/Callback",
            "http://localhost:5001/Auth/Callback",
            "http://localhost:5000/Auth/Callback"
          ],
          "allowedLogoutRedirectUris": [
            "https://localhost:5001/",
            "https://localhost:5001/Auth/Logout",
            "http://localhost:5001/",
            "http://localhost:5000/"
          ],
          "oboEnabled": true,
          "oboAllowedTargetAudiences": ["obo-demo-api"],
          "oboAllowedScopes": ["openid", "profile", "email", "api.read"],
          "oboMaxLifetimeMinutes": 15,
          "oboMaxDelegationDepth": 1
        },
        {
          "clientId": "obo-demo-api",
          "clientName": "OBO Demo API",
          "realm": "admin",
          "requirePkce": false,
          "requireConsent": false,
          "allowedScopes": ["openid", "profile", "email", "api.read"],
          "clientSecretEnv": "OBO_DEMO_API_SECRET"
        },
        {
          "clientId": "react-spa-demo",
          "clientName": "React SPA Demo Client",
          "realm": "admin",
          "requirePkce": true,
          "requireConsent": false,
          "autoApprovalMode": "All",
          "isPublicClient": true,
          "allowedScopes": [
            "openid",
            "profile",
            "email"
          ],
          "allowedLoginRedirectUris": [
            "http://localhost:3000/callback",
            "http://localhost:3000/"
          ],
          "allowedLogoutRedirectUris": [
            "http://localhost:3000/",
            "http://localhost:3000/logout"
          ]
        },
        {
          "clientId": "go-client-demo",
          "clientName": "Go Web Client Demo",
          "realm": "admin",
          "requirePkce": true,
          "requireConsent": false,
          "autoApprovalMode": "All",
          "allowedScopes": [
            "openid",
            "profile",
            "email",
            "offline_access"
          ],
          "clientSecretEnv": "GO_CLIENT_SECRET",
          "allowedLoginRedirectUris": [
            "http://localhost:5080/callback",
            "https://localhost:5080/callback"
          ],
          "allowedLogoutRedirectUris": [
            "http://localhost:5080/",
            "http://localhost:5080/logout",
            "https://localhost:5080/",
            "https://localhost:5080/logout"
          ]
        }
      ],
      "users": [
        {
          "username": "demo@example.com",
          "email": "demo@example.com",
          "password": "Demo123!",
          "displayName": "Demo User",
          "emailConfirmed": true,
          "realm": "admin"
        }
      ]
    }
  ]
}
```

---

## Environment Variables to Add

In `docker-compose.yml` for mrwho-oidc:

```yaml
OBO_DEMO_API_SECRET: ${OBO_DEMO_API_SECRET:-demo-obo-api-secret-123}
```

---

## Testing Checklist

- [ ] Seed manifest applies without errors
- [ ] `dotnet-mvc-demo` client has OBO policy configured
- [ ] `obo-demo-api` client is created
- [ ] User can log into dotnet-mvc-demo
- [ ] Token exchange succeeds at `/token` endpoint
- [ ] OBO Demo API validates exchanged token
- [ ] API response includes correct `act` claim
- [ ] API response shows original user as subject
- [ ] API response shows dotnet-mvc-demo as actor

---

## References

- [OBO Client Policy Documentation](../../MrWhoOidc/docs/obo-client-policy.md)
- [Token Exchange Implementation](../../MrWhoOidc/MrWhoOidc.WebAuth/TokenEndpoint/Grants/TokenExchangeGrantHandler.cs)
- [MrWhoOidc.Client Token Exchange](../../MrWho/src/MrWhoOidc.Client/Tokens/TokenExchangeRequest.cs)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [Existing TestApi Example](../../MrWhoOidc/Examples/MrWhoOidc.TestApi/)
