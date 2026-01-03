# OBO vs M2M Comparison Demo Implementation Plan

This document describes the plan for extending the existing OBO demo to include a **Machine-to-Machine (M2M)** / **Client Credentials** flow comparison. The goal is to showcase the differences between calling an API **on behalf of a user** (OBO) versus calling an API **as a machine identity** (M2M).

## Overview

### Goal

Demonstrate and compare two token acquisition strategies from the **same client application**:

| Aspect | OBO (On-Behalf-Of) | M2M (Client Credentials) |
|--------|-------------------|--------------------------|
| Grant Type | `urn:ietf:params:oauth:grant-type:token-exchange` | `client_credentials` |
| Identity | Delegated user identity | Application/machine identity |
| Subject (`sub`) | User ID | Client ID |
| Actor (`act`) | Client acting on user's behalf | N/A |
| Use Case | User-initiated actions | Background jobs, service calls |

### Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  User Browser   │──────│ dotnet-mvc-demo │──────│  MrWhoOidc IdP  │
│                 │      │  (Client App)   │      │  (Auth Server)  │
└─────────────────┘      └────────┬────────┘      └─────────────────┘
                                  │                        │
                                  │                        │
              ┌───────────────────┼───────────────────┐    │
              │                   │                   │    │
              ▼                   ▼                   │    │
    ┌─────────────────┐  ┌─────────────────┐         │    │
    │  OBO Token      │  │  M2M Token      │         │    │
    │  Exchange       │  │  (client_creds) │◄────────┼────┘
    │  (user context) │  │  (app context)  │         │
    └────────┬────────┘  └────────┬────────┘         │
             │                    │                  │
             └─────────┬──────────┘                  │
                       ▼                             │
              ┌─────────────────┐                    │
              │  obo-demo-api   │  Validates tokens  │
              │  GET /identity  │  from both flows   │
              │  (unified)      │◄───────────────────┘
              └─────────────────┘
```

---

## Key Design Decision: Unified API Endpoint

Instead of separate endpoints for OBO and M2M, we'll use a **single `/identity` endpoint** that introspects the incoming token and returns contextual information based on how the call was made:

| Token Type | Response Shape |
|------------|----------------|
| OBO (has `act` claim) | `{ type: "user", subject, name, email, actor, ... }` |
| M2M (no `act`, sub = client_id) | `{ type: "machine", clientId, clientName, ... }` |

This design makes the comparison crystal clear in the UI.

---

## Components to Create/Modify

### 1. Modify: OBO Demo API (`MrWho/demos/obo-demo-api/`)

#### 1.1 New Unified Endpoint: `GET /identity`

Replace or augment the existing `/me` endpoint with a smarter `/identity` endpoint.

**File:** `obo-demo-api/Program.cs`

```csharp
// GET /identity - Returns information based on call type (OBO vs M2M)
app.MapGet("/identity", async (ClaimsPrincipal user, HttpContext context, 
    IHttpClientFactory httpClientFactory, 
    IOptionsMonitor<MrWhoOidcClientOptions> optionsMonitor, 
    ILogger<Program> logger) =>
{
    var subject = user.FindFirst("sub")?.Value;
    var audience = user.FindFirst("aud")?.Value;
    var scopes = user.FindFirst("scope")?.Value?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var issuedAt = user.FindFirst("iat")?.Value;
    var expiresAt = user.FindFirst("exp")?.Value;
    
    // Check for actor claim to determine call type
    var actClaim = user.FindFirst("act")?.Value;
    
    if (!string.IsNullOrEmpty(actClaim))
    {
        // --- OBO CALL: Token has an actor ---
        string? actorClientId = null;
        try 
        {
            using var doc = JsonDocument.Parse(actClaim);
            if (doc.RootElement.TryGetProperty("sub", out var subProp))
            {
                actorClientId = subProp.GetString();
            }
        }
        catch
        {
            actorClientId = actClaim;
        }

        // Fetch user info from IdP
        JsonElement? userInfo = null;
        var accessToken = await context.GetTokenAsync("access_token");
        if (!string.IsNullOrEmpty(accessToken))
        {
            userInfo = await FetchUserInfoAsync(accessToken, optionsMonitor.CurrentValue, 
                httpClientFactory, logger);
        }

        var name = user.FindFirst("name")?.Value;
        var email = user.FindFirst("email")?.Value;
        
        // Enrich from userInfo if missing
        if (userInfo.HasValue)
        {
            if (string.IsNullOrEmpty(name) && userInfo.Value.TryGetProperty("name", out var n))
                name = n.GetString();
            if (string.IsNullOrEmpty(email) && userInfo.Value.TryGetProperty("email", out var e))
                email = e.GetString();
        }

        return Results.Ok(new
        {
            type = "user",
            message = "Called on behalf of user (OBO flow)",
            subject,
            name,
            email,
            actor = actorClientId,
            audience,
            scopes,
            issuedAt,
            expiresAt,
            userInfo
        });
    }
    else
    {
        // --- M2M CALL: No actor, subject is the client ---
        // In client_credentials flow, 'sub' is typically the client_id
        // Additional claims may include azp (authorized party), client_id, etc.
        var clientId = user.FindFirst("client_id")?.Value 
                    ?? user.FindFirst("azp")?.Value 
                    ?? subject;
        
        return Results.Ok(new
        {
            type = "machine",
            message = "Called as machine identity (M2M / Client Credentials flow)",
            clientId,
            subject,
            audience,
            scopes,
            issuedAt,
            expiresAt
        });
    }
}).RequireAuthorization();

// Helper method for user info fetching (extract from existing code)
static async Task<JsonElement?> FetchUserInfoAsync(string accessToken, 
    MrWhoOidcClientOptions clientOptions, 
    IHttpClientFactory httpClientFactory, 
    ILogger logger)
{
    var userInfoEndpoint = $"{clientOptions.Issuer?.TrimEnd('/')}/userinfo";
    var client = httpClientFactory.CreateClient("UserInfoClient");
    
    var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    
    try 
    {
        var response = await client.SendAsync(request);
        if (response.IsSuccessStatusCode)
        {
            return await response.Content.ReadFromJsonAsync<JsonElement>();
        }
        logger.LogWarning("UserInfo endpoint returned: {StatusCode}", response.StatusCode);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to call UserInfo endpoint");
    }
    return null;
}
```

#### 1.2 Keep `/me` as Alias (Optional)

For backwards compatibility, keep `/me` pointing to the same logic or redirect to `/identity`.

---

### 2. Modify: dotnet-mvc-client (`MrWho/demos/dotnet-mvc-client/`)

#### 2.1 New Service: `M2MApiClient`

A new HTTP client service that acquires tokens via **client credentials** (no user context).

**File:** `Services/M2MApiClient.cs`

```csharp
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace MrWhoOidc.RazorClient.Services;

public sealed class M2MApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<M2MApiClient> _logger;

    public M2MApiClient(HttpClient httpClient, ILogger<M2MApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<M2MApiResponse?> GetIdentityAsync(CancellationToken ct = default)
    {
        using var response = await _httpClient.GetAsync("identity", ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("M2M API call failed: {StatusCode}", response.StatusCode);
            return null;
        }
        return await response.Content.ReadFromJsonAsync<M2MApiResponse>(ct);
    }

    public sealed record M2MApiResponse(
        string? Type,
        string? Message,
        string? ClientId,
        string? Subject,
        string? Audience,
        IEnumerable<string>? Scopes,
        string? IssuedAt,
        string? ExpiresAt);
}
```

#### 2.2 Update `OboApiClient` to Use `/identity`

Update the existing client to call the new unified endpoint.

**File:** `Services/OboApiClient.cs`

```csharp
public async Task<OboApiResponse?> GetIdentityAsync(CancellationToken ct = default)
{
    using var response = await _httpClient.GetAsync("identity", ct);
    if (!response.IsSuccessStatusCode)
    {
        _logger.LogWarning("OBO API call failed: {StatusCode}", response.StatusCode);
        return null;
    }
    return await response.Content.ReadFromJsonAsync<OboApiResponse>(ct);
}

public sealed record OboApiResponse(
    string? Type,
    string? Message,
    string? Subject,
    string? Name,
    string? Email,
    string? Actor,
    string? Audience,
    IEnumerable<string>? Scopes,
    string? IssuedAt,
    string? ExpiresAt,
    JsonElement? UserInfo);
```

#### 2.3 DI Registration for M2M Client

**File:** `Program.cs`

Add client credentials token handler registration:

```csharp
// M2M API Client (Client Credentials flow)
builder.Services.AddHttpClient<M2MApiClient>((sp, client) =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        var baseAddress = config["M2MApi:BaseAddress"];
        if (!string.IsNullOrWhiteSpace(baseAddress) && Uri.TryCreate(baseAddress, UriKind.Absolute, out var uri))
        {
            client.BaseAddress = uri;
        }
    })
    .ConfigurePrimaryHttpMessageHandler(sp =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        var acceptAny = config.GetValue<bool>("MrWhoOidc:DangerousAcceptAnyServerCertificateValidator");
        if (acceptAny)
        {
            return new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
        }
        return new HttpClientHandler();
    })
    .AddMrWhoClientCredentialsTokenHandler("obo-demo-api");  // <-- New extension method
```

> **Note:** The `AddMrWhoClientCredentialsTokenHandler` extension needs to be added to `MrWhoOidc.Client` if it doesn't exist. See Section 3 below.

#### 2.4 Configuration Updates

**File:** `appsettings.json`

```json
{
  "MrWhoOidc": {
    "Issuer": "https://localhost:8443",
    "ClientId": "dotnet-mvc-demo",
    "ClientSecret": "your-client-secret-from-admin-ui",
    "Scopes": ["openid", "profile", "email", "offline_access", "api.read"],
    "UsePkce": true,
    "RequireHttpsMetadata": true,
    "OnBehalfOf": {
      "obo-demo-api": {
        "Scope": "openid profile email api.read",
        "Audience": "obo-demo-api",
        "CacheLifetime": "00:05:00"
      }
    },
    "ClientCredentials": {
      "obo-demo-api": {
        "Scope": "api.read",
        "CacheLifetime": "00:05:00"
      }
    }
  },
  "OboApi": {
    "BaseAddress": "https://localhost:7200"
  },
  "M2MApi": {
    "BaseAddress": "https://localhost:7200"
  }
}
```

> **Note:** `OboApi` and `M2MApi` point to the same API but use different token acquisition strategies. This is intentional for the comparison demo.

---

### 3. Extend: MrWhoOidc.Client Library

#### 3.1 New Extension: `AddMrWhoClientCredentialsTokenHandler`

If not already present, add a delegating handler that acquires tokens via the client credentials grant.

**File:** `MrWhoOidc.Client/DependencyInjection/HttpClientBuilderExtensions.cs`

```csharp
/// <summary>
/// Adds a delegating handler that attaches a client credentials (M2M) access token 
/// to outgoing requests.
/// </summary>
public static IHttpClientBuilder AddMrWhoClientCredentialsTokenHandler(
    this IHttpClientBuilder builder,
    string audienceKey)
{
    builder.AddHttpMessageHandler(sp =>
    {
        var manager = sp.GetRequiredService<IMrWhoClientCredentialsManager>();
        return new MrWhoClientCredentialsTokenHandler(manager, audienceKey);
    });
    return builder;
}
```

#### 3.2 New Service: `IMrWhoClientCredentialsManager`

```csharp
public interface IMrWhoClientCredentialsManager
{
    /// <summary>
    /// Acquires an access token using the client credentials grant.
    /// </summary>
    ValueTask<string?> AcquireTokenAsync(string audienceKey, CancellationToken ct = default);
}
```

Implementation will:
1. Read configuration from `MrWhoOidc:ClientCredentials:{audienceKey}`
2. Call the token endpoint with `grant_type=client_credentials`
3. Cache the token based on `CacheLifetime` or token expiry

#### 3.3 New Handler: `MrWhoClientCredentialsTokenHandler`

```csharp
internal sealed class MrWhoClientCredentialsTokenHandler : DelegatingHandler
{
    private readonly IMrWhoClientCredentialsManager _manager;
    private readonly string _audienceKey;

    public MrWhoClientCredentialsTokenHandler(
        IMrWhoClientCredentialsManager manager, 
        string audienceKey)
    {
        _manager = manager;
        _audienceKey = audienceKey;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, 
        CancellationToken ct)
    {
        var token = await _manager.AcquireTokenAsync(_audienceKey, ct);
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = 
                new AuthenticationHeaderValue("Bearer", token);
        }
        return await base.SendAsync(request, ct);
    }
}
```

---

### 4. New Page: Comparison Demo

#### 4.1 Page Model

**File:** `Pages/TokenComparison.cshtml.cs`

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using MrWhoOidc.RazorClient.Services;

namespace MrWhoOidc.RazorClient.Pages;

[Authorize]
public class TokenComparisonModel : PageModel
{
    private readonly OboApiClient _oboApi;
    private readonly M2MApiClient _m2mApi;

    public TokenComparisonModel(OboApiClient oboApi, M2MApiClient m2mApi)
    {
        _oboApi = oboApi;
        _m2mApi = m2mApi;
    }

    public OboApiClient.OboApiResponse? OboResponse { get; private set; }
    public M2MApiClient.M2MApiResponse? M2MResponse { get; private set; }
    public string? OboJson { get; private set; }
    public string? M2MJson { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnPostCallBothAsync()
    {
        try
        {
            // Call both APIs in parallel
            var oboTask = _oboApi.GetIdentityAsync();
            var m2mTask = _m2mApi.GetIdentityAsync();
            
            await Task.WhenAll(oboTask, m2mTask);
            
            OboResponse = oboTask.Result;
            M2MResponse = m2mTask.Result;
            
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            OboJson = OboResponse is not null 
                ? JsonSerializer.Serialize(OboResponse, jsonOptions) 
                : null;
            M2MJson = M2MResponse is not null 
                ? JsonSerializer.Serialize(M2MResponse, jsonOptions) 
                : null;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        return Page();
    }
    
    public async Task<IActionResult> OnPostCallOboAsync()
    {
        try
        {
            OboResponse = await _oboApi.GetIdentityAsync();
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            OboJson = OboResponse is not null 
                ? JsonSerializer.Serialize(OboResponse, jsonOptions) 
                : null;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"OBO Error: {ex.Message}";
        }
        return Page();
    }
    
    public async Task<IActionResult> OnPostCallM2MAsync()
    {
        try
        {
            M2MResponse = await _m2mApi.GetIdentityAsync();
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            M2MJson = M2MResponse is not null 
                ? JsonSerializer.Serialize(M2MResponse, jsonOptions) 
                : null;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"M2M Error: {ex.Message}";
        }
        return Page();
    }
}
```

#### 4.2 Razor View

**File:** `Pages/TokenComparison.cshtml`

```html
@page
@model MrWhoOidc.RazorClient.Pages.TokenComparisonModel
@{
    ViewData["Title"] = "OBO vs M2M Token Comparison";
}

<h1>OBO vs M2M Token Comparison</h1>
<p class="lead">
    Compare how the same API responds to tokens acquired via different OAuth flows.
</p>

<div class="row mb-4">
    <div class="col">
        <form method="post">
            <button type="submit" asp-page-handler="CallBoth" class="btn btn-primary btn-lg">
                Call API with Both Flows
            </button>
            <button type="submit" asp-page-handler="CallObo" class="btn btn-outline-secondary">
                OBO Only
            </button>
            <button type="submit" asp-page-handler="CallM2M" class="btn btn-outline-secondary">
                M2M Only
            </button>
        </form>
    </div>
</div>

@if (!string.IsNullOrEmpty(Model.ErrorMessage))
{
    <div class="alert alert-danger">@Model.ErrorMessage</div>
}

<div class="row">
    <!-- OBO Response -->
    <div class="col-md-6">
        <div class="card @(Model.OboResponse?.Type == "user" ? "border-success" : "")">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0">
                    <i class="bi bi-person"></i> On-Behalf-Of (User Context)
                </h5>
            </div>
            <div class="card-body">
                @if (Model.OboResponse is not null)
                {
                    <dl>
                        <dt>Type</dt>
                        <dd><span class="badge bg-success">@Model.OboResponse.Type</span></dd>
                        
                        <dt>Subject (User ID)</dt>
                        <dd><code>@Model.OboResponse.Subject</code></dd>
                        
                        <dt>User Name</dt>
                        <dd>@(Model.OboResponse.Name ?? "N/A")</dd>
                        
                        <dt>Email</dt>
                        <dd>@(Model.OboResponse.Email ?? "N/A")</dd>
                        
                        <dt>Actor (Client)</dt>
                        <dd><code>@(Model.OboResponse.Actor ?? "N/A")</code></dd>
                        
                        <dt>Audience</dt>
                        <dd><code>@Model.OboResponse.Audience</code></dd>
                        
                        <dt>Scopes</dt>
                        <dd>@string.Join(", ", Model.OboResponse.Scopes ?? [])</dd>
                    </dl>
                    
                    <details>
                        <summary>Raw JSON Response</summary>
                        <pre class="bg-light p-2 mt-2"><code>@Model.OboJson</code></pre>
                    </details>
                }
                else
                {
                    <p class="text-muted">Click a button above to call the API.</p>
                }
            </div>
        </div>
    </div>
    
    <!-- M2M Response -->
    <div class="col-md-6">
        <div class="card @(Model.M2MResponse?.Type == "machine" ? "border-primary" : "")">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0">
                    <i class="bi bi-robot"></i> Machine-to-Machine (App Context)
                </h5>
            </div>
            <div class="card-body">
                @if (Model.M2MResponse is not null)
                {
                    <dl>
                        <dt>Type</dt>
                        <dd><span class="badge bg-primary">@Model.M2MResponse.Type</span></dd>
                        
                        <dt>Client ID</dt>
                        <dd><code>@Model.M2MResponse.ClientId</code></dd>
                        
                        <dt>Subject</dt>
                        <dd><code>@Model.M2MResponse.Subject</code></dd>
                        
                        <dt>Audience</dt>
                        <dd><code>@Model.M2MResponse.Audience</code></dd>
                        
                        <dt>Scopes</dt>
                        <dd>@string.Join(", ", Model.M2MResponse.Scopes ?? [])</dd>
                    </dl>
                    
                    <details>
                        <summary>Raw JSON Response</summary>
                        <pre class="bg-light p-2 mt-2"><code>@Model.M2MJson</code></pre>
                    </details>
                }
                else
                {
                    <p class="text-muted">Click a button above to call the API.</p>
                }
            </div>
        </div>
    </div>
</div>

<hr class="my-4" />

<h4>Key Differences Explained</h4>
<table class="table table-bordered">
    <thead class="table-light">
        <tr>
            <th>Aspect</th>
            <th class="text-success">OBO (On-Behalf-Of)</th>
            <th class="text-primary">M2M (Client Credentials)</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><strong>Grant Type</strong></td>
            <td><code>urn:ietf:params:oauth:grant-type:token-exchange</code></td>
            <td><code>client_credentials</code></td>
        </tr>
        <tr>
            <td><strong>Identity</strong></td>
            <td>Delegated user identity</td>
            <td>Application/machine identity</td>
        </tr>
        <tr>
            <td><strong>Subject Claim</strong></td>
            <td>User's unique ID</td>
            <td>Client ID (application)</td>
        </tr>
        <tr>
            <td><strong>Actor Claim</strong></td>
            <td>Present (identifies the client acting on behalf)</td>
            <td>Not present</td>
        </tr>
        <tr>
            <td><strong>User Info</strong></td>
            <td>Available (name, email, etc.)</td>
            <td>Not available</td>
        </tr>
        <tr>
            <td><strong>Use Cases</strong></td>
            <td>User-initiated actions requiring delegation</td>
            <td>Background jobs, service-to-service, scheduled tasks</td>
        </tr>
    </tbody>
</table>
```

#### 4.3 Navigation Update

**File:** `Pages/Shared/_Layout.cshtml`

```html
<nav>
    <a asp-page="/Index">Home</a>
    <a asp-page="/OboDemo">On-Behalf-Of Demo</a>
    <a asp-page="/TokenComparison">OBO vs M2M</a>  <!-- NEW -->
</nav>
```

---

### 5. OIDC Configuration Updates

#### 5.1 Seed Manifest (`oidc-seed-manifest.json`)

Ensure the `dotnet-mvc-demo` client is configured for client credentials grant:

```json
{
  "clientId": "dotnet-mvc-demo",
  "clientName": ".NET MVC Demo Client",
  "realm": "admin",
  "requirePkce": true,
  "requireConsent": false,
  "autoApprovalMode": "All",
  "allowedScopes": ["openid", "profile", "email", "offline_access", "api.read"],
  "allowedGrantTypes": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "client_credentials"  // <-- ADD THIS
  ],
  "clientSecretEnv": "DOTNET_MVC_DEMO_SECRET",
  "oboPolicy": {
    "allowed": true,
    "targetAudiences": ["obo-demo-api"]
  }
}
```

---

## Implementation Order

### Phase 1: API Changes (obo-demo-api)
1. Add the unified `/identity` endpoint
2. Keep `/me` as an alias for backward compatibility
3. Test with existing OBO setup to ensure no regression

### Phase 2: Client Library (MrWhoOidc.Client)
1. Add `IMrWhoClientCredentialsManager` interface
2. Implement `MrWhoClientCredentialsManager` with token caching
3. Add `MrWhoClientCredentialsTokenHandler` delegating handler
4. Add `AddMrWhoClientCredentialsTokenHandler` extension method
5. Wire up in `AddMrWhoOidcClient` registration

### Phase 3: MVC Client Changes (dotnet-mvc-client)
1. Add `M2MApiClient` service
2. Update `OboApiClient` to use `/identity`
3. Register `M2MApiClient` with client credentials handler
4. Add configuration for `ClientCredentials` section
5. Create `TokenComparison` page and model
6. Update navigation

### Phase 4: Seed/Config Updates
1. Update `oidc-seed-manifest.json` to allow `client_credentials` grant
2. Update environment templates if needed

### Phase 5: Documentation & Testing
1. Update demo README
2. Add manual test scenarios
3. Verify Docker Compose deployment

---

## Configuration Reference

### Full `appsettings.json` Structure

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "MrWhoOidc": {
    "Issuer": "https://localhost:8443",
    "ClientId": "dotnet-mvc-demo",
    "ClientSecret": "your-client-secret-from-admin-ui",
    "Scopes": ["openid", "profile", "email", "offline_access", "api.read"],
    "UsePkce": true,
    "RequireHttpsMetadata": true,
    "DangerousAcceptAnyServerCertificateValidator": false,
    
    "OnBehalfOf": {
      "obo-demo-api": {
        "Scope": "openid profile email api.read",
        "Audience": "obo-demo-api",
        "CacheLifetime": "00:05:00"
      }
    },
    
    "ClientCredentials": {
      "obo-demo-api": {
        "Scope": "api.read",
        "CacheLifetime": "00:05:00"
      }
    }
  },
  
  "OboApi": {
    "BaseAddress": "https://localhost:7200"
  },
  "M2MApi": {
    "BaseAddress": "https://localhost:7200"
  }
}
```

---

## Success Criteria

1. **Side-by-side comparison**: User can see OBO and M2M responses next to each other
2. **Clear differentiation**: Response `type` field clearly shows "user" vs "machine"
3. **Same API, different tokens**: Both calls hit the same `/identity` endpoint
4. **User context preserved in OBO**: Name, email, and `act` claim visible
5. **Machine identity in M2M**: Only client ID visible, no user details
6. **Token caching**: Both flows cache tokens appropriately to avoid redundant token requests

---

## Security Considerations

1. **Client Secret Protection**: The M2M flow requires the client secret. Ensure it's stored securely (environment variables, Key Vault, etc.)
2. **Scope Minimization**: M2M tokens should request only necessary scopes (e.g., `api.read` without `openid profile email`)
3. **Audience Validation**: The API must validate the `aud` claim matches expected audience
4. **Logging**: Log which flow was used but never log token contents

---

## Future Enhancements

1. **Token Introspection View**: Show decoded JWT side-by-side
2. **Timing Comparison**: Show token acquisition latency for each flow
3. **Refresh Token Demo**: Add OBO token refresh demonstration
4. **DPoP Support**: Add proof-of-possession comparison when available
