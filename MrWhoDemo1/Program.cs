using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllers(); // Add controllers for back-channel logout

// Add memory cache for session invalidation tracking
builder.Services.AddMemoryCache();

// CRITICAL: Add distributed memory cache for session support
builder.Services.AddDistributedMemoryCache();

// Add session support for logout notifications
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".MrWho.Demo1.Session";
});

// Add HttpClient to call Demo API with user access token
builder.Services.AddHttpClient("DemoApi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7162/"); // Matches Demo API https profile
});

// NEW: HttpClient for direct MrWho identity server API (administration API) – uses client credentials (mrwho_m2m)
builder.Services.AddHttpClient("MrWhoApi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7113/");
});

// Delegating handler to attach access token from current user
builder.Services.AddTransient<DelegatingHandler, UserAccessTokenHandler>();

// Replace default primary handler pipeline for named client
builder.Services.AddHttpClient("DemoApiWithAuth", client =>
{
    client.BaseAddress = new Uri("https://localhost:7162/");
}).AddHttpMessageHandler<UserAccessTokenHandler>();

// CRITICAL: Clear default claim mappings to preserve JWT claim names
Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

// CORRECTED: Use standard OIDC scheme - session isolation handled server-side
const string demo1CookieScheme = "Demo1Cookies";

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = demo1CookieScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme; // Use standard OIDC
    options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme; // Use standard OIDC
})
.AddCookie(demo1CookieScheme, options =>
{
    options.Cookie.Name = ".MrWho.Demo1"; // Client-specific cookie name for local session
    options.Cookie.Path = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(2); // Demo session timeout
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    // FIXED: Use relative path that will redirect back to the identity server during OIDC flow
    options.AccessDeniedPath = "/Account/AccessDenied";

    // CRITICAL: Add event to check for session invalidation on each request
    options.Events.OnValidatePrincipal = async context =>
    {
        var cache = context.HttpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>();
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();

        if (context.Principal?.Identity?.IsAuthenticated == true)
        {
            var subjectClaim = context.Principal.FindFirst("sub")?.Value;

            if (!string.IsNullOrEmpty(subjectClaim))
            {
                // Check if this subject has been logged out via back-channel logout
                if (cache.TryGetValue($"logout_{subjectClaim}", out var logoutInfo))
                {
                    logger.LogInformation("Demo1 session invalidated for subject {Subject} due to back-channel logout", subjectClaim);

                    // Reject the principal to force re-authentication
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(demo1CookieScheme);

                    // Remove the logout notification after processing
                    cache.Remove($"logout_{subjectClaim}");
                }
            }
        }
    };
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => // Use standard OIDC scheme
{
    options.SignInScheme = demo1CookieScheme;
    options.Authority = "https://localhost:7113"; // Identity Server
    options.ClientId = "mrwho_demo1";
    options.ClientSecret = "PyfrZln6d2ifAbdL_2gr316CERUMyzfpgmxJ1J3xJsWUnfHGakcvjWenB_OwQqnv";
    options.ResponseType = OpenIdConnectResponseType.Code;

    // Scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("roles");
    options.Scope.Add("offline_access");
    options.Scope.Add("api.read");
    options.Scope.Add("api.write");

    // Save tokens for display and API calls
    options.SaveTokens = true;

    // Use PKCE for additional security
    options.UsePkce = true;

    // Force skip PAR regardless of discovery or defaults
    options.Events ??= new OpenIdConnectEvents();
    options.Events.OnPushAuthorization = context =>
    {
        context.SkipPush();
        return Task.CompletedTask;
    };

    // SSL configuration for production authority
    options.RequireHttpsMetadata = true; // Production: require HTTPS metadata

    // Disable the default inbound claim type mappings to preserve JWT claim names
    options.MapInboundClaims = false;

    // Map claims to preserve JWT claim names
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.RoleClaimType = "role";

    // Clear default claim type mappings to ensure we get the raw JWT claims
    options.ClaimActions.Clear();

    // Map the claims we want to preserve from the ID token
    options.ClaimActions.MapUniqueJsonKey("sub", "sub");
    options.ClaimActions.MapUniqueJsonKey("name", "name");
    options.ClaimActions.MapUniqueJsonKey("given_name", "given_name");
    options.ClaimActions.MapUniqueJsonKey("family_name", "family_name");
    options.ClaimActions.MapUniqueJsonKey("email", "email");
    options.ClaimActions.MapUniqueJsonKey("email_verified", "email_verified");
    options.ClaimActions.MapUniqueJsonKey("preferred_username", "preferred_username");
    options.ClaimActions.MapUniqueJsonKey("role", "role");

    // CRITICAL FIX: Configure post-logout redirect to home page (which no longer requires auth)
    options.SignedOutRedirectUri = "/?logout=success";

    // Events for diagnostics
    options.Events.OnTokenValidated = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogDebug("Demo1 claims in ID token: {Claims}",
            string.Join(", ", context.Principal?.Claims.Select(c => $"{c.Type}={c.Value}") ?? Array.Empty<string>()));
        return Task.CompletedTask;
    };
    options.Events.OnAuthenticationFailed = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError("Demo1 Authentication failed: {Error}", context.Exception?.Message);
        return Task.CompletedTask;
    };
});

var app = builder.Build();

// Log current environment information
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("?? MrWho Demo1 Application starting up...");
logger.LogInformation("?? Environment: {Environment}", app.Environment.EnvironmentName);
logger.LogInformation("?? Application Name: {ApplicationName}", app.Environment.ApplicationName);
logger.LogInformation("?? Content Root: {ContentRoot}", app.Environment.ContentRootPath);
logger.LogInformation("?? Web Root: {WebRoot}", app.Environment.WebRootPath);
logger.LogInformation("?? Is Development: {IsDevelopment}", app.Environment.IsDevelopment());
logger.LogInformation("?? Is Production: {IsProduction}", app.Environment.IsProduction());
logger.LogInformation("?? Is Staging: {IsStaging}", app.Environment.IsStaging());

app.MapDefaultEndpoints();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

// Add session middleware for logout notifications
app.UseSession();

// Add authentication middleware
app.UseAuthentication();
app.UseAuthorization();

// Map controllers for back-channel logout
app.MapControllers();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

// Simple endpoint to call the protected Demo API using the user access token
app.MapGet("/call-api", async (IHttpClientFactory factory, HttpContext http) =>
{
    if (http.User.Identity?.IsAuthenticated != true)
    {
        return Results.Json(new { error = "not_authenticated" }, statusCode: 401);
    }

    var accessToken = await http.GetTokenAsync("access_token");
    if (string.IsNullOrEmpty(accessToken))
    {
        return Results.Json(new { error = "no_access_token" }, statusCode: 400);
    }

    var client = factory.CreateClient("DemoApi");
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

    var response = await client.GetAsync("WeatherForecast");
    var content = await response.Content.ReadAsStringAsync();
    return Results.Json(new { status = (int)response.StatusCode, ok = response.IsSuccessStatusCode, body = content });
}).RequireAuthorization();

// Machine-to-machine demo: invoke API's internal client_credentials test endpoint (no user context required)
app.MapGet("/call-m2m", async (IHttpClientFactory factory) =>
{
    var client = factory.CreateClient("DemoApi");
    var response = await client.GetAsync("m2m-test/obtain-token-and-call");
    var body = await response.Content.ReadAsStringAsync();
    return Results.Json(new { status = (int)response.StatusCode, ok = response.IsSuccessStatusCode, raw = body });
});

// NEW: Client credentials call using mrwho_m2m client to fetch realms from MrWho API (requires mrwho.use)
// The endpoint itself performs token request then API call for demo clarity.
app.MapGet("/call-mrwho-realms", async () =>
{
    // Perform client_credentials token request manually
    using var http = new HttpClient();
    var tokenReq = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7113/connect/token")
    {
        Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "mrwho_m2m",
            ["client_secret"] = "FTZvvlIIFdmtBg7IdBql9EEXRDj1xwLmi1qW9fGbJBY",
            ["scope"] = "mrwho.use"
        })
    };
    var tokenResp = await http.SendAsync(tokenReq);
    var tokenJson = await tokenResp.Content.ReadAsStringAsync();
    if (!tokenResp.IsSuccessStatusCode)
    {
        return Results.Json(new { stage = "token", status = (int)tokenResp.StatusCode, ok = false, body = tokenJson });
    }
    string? accessToken = null;
    try
    {
        var doc = System.Text.Json.JsonDocument.Parse(tokenJson);
        accessToken = doc.RootElement.GetProperty("access_token").GetString();
    }
    catch { }
    if (string.IsNullOrEmpty(accessToken)) {
        return Results.Json(new { stage = "token-parse", ok = false, body = tokenJson });
    }

    // Call protected realms endpoint on identity server API
    var apiClient = new HttpClient { BaseAddress = new Uri("https://localhost:7113/") };
    apiClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    var realmsResp = await apiClient.GetAsync("api/realms?page=1&pageSize=20");
    var realmsBody = await realmsResp.Content.ReadAsStringAsync();
    return Results.Json(new { stage = "realms", status = (int)realmsResp.StatusCode, ok = realmsResp.IsSuccessStatusCode, body = realmsBody });
});

// Add health check endpoint
app.MapGet("/health", () => Results.Ok(new
{
    Status = "Healthy",
    Application = "MrWho Demo 1",
    Timestamp = DateTime.UtcNow,
    Version = "1.0.0"
}));

// Add debug endpoints for troubleshooting authentication
if (app.Environment.IsDevelopment())
{
    app.MapGet("/debug/auth", (HttpContext context) =>
    {
        var isAuthenticated = context.User.Identity?.IsAuthenticated == true;
        var authType = context.User.Identity?.AuthenticationType;
        var name = context.User.Identity?.Name;
        var claims = context.User.Claims.Select(c => new { c.Type, c.Value }).ToList();

        return Results.Json(new
        {
            IsAuthenticated = isAuthenticated,
            AuthenticationType = authType,
            Name = name,
            ClaimsCount = claims.Count,
            Claims = claims,
            Cookies = context.Request.Cookies.Select(c => new { c.Key, Length = c.Value.Length }).ToList()
        });
    });

    app.MapPost("/debug/logout", async (HttpContext context) =>
    {
        await context.SignOutAsync(demo1CookieScheme);
        await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme); // Use standard OIDC scheme

        return Results.Ok(new { Message = "Signed out from Demo1 using standard schemes with server-side isolation", Timestamp = DateTime.UtcNow });
    });

    app.MapGet("/debug/tokens", async (HttpContext context) =>
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return Results.Json(new { Error = "Not authenticated" });
        }

        var accessToken = await context.GetTokenAsync("access_token");
        var refreshToken = await context.GetTokenAsync("refresh_token");
        var idToken = await context.GetTokenAsync("id_token");

        return Results.Json(new
        {
            HasAccessToken = !string.IsNullOrEmpty(accessToken),
            AccessTokenLength = accessToken?.Length ?? 0,
            HasRefreshToken = !string.IsNullOrEmpty(refreshToken),
            RefreshTokenLength = refreshToken?.Length ?? 0,
            HasIdToken = !string.IsNullOrEmpty(idToken),
            IdTokenLength = idToken?.Length ?? 0
        });
    });

    // Debug endpoint to test logout flow step by step
    app.MapGet("/debug/logout-flow", async (HttpContext context) =>
    {
        var steps = new List<object>();

        // Step 1: Check current authentication status
        var isAuthenticated = context.User.Identity?.IsAuthenticated == true;
        steps.Add(new { step = 1, description = "Check authentication", result = isAuthenticated });

        if (isAuthenticated)
        {
            // Step 2: Check available tokens
            var accessToken = await context.GetTokenAsync("access_token");
            var refreshToken = await context.GetTokenAsync("refresh_token");
            var idToken = await context.GetTokenAsync("id_token");

            steps.Add(new
            {
                step = 2,
                description = "Check tokens",
                result = new
                {
                    hasAccessToken = !string.IsNullOrEmpty(accessToken),
                    hasRefreshToken = !string.IsNullOrEmpty(refreshToken),
                    hasIdToken = !string.IsNullOrEmpty(idToken)
                }
            });

            // Step 3: Check cookies
            var cookies = context.Request.Cookies
                .Where(c => c.Key.Contains("Demo1") || c.Key.Contains("AspNet"))
                .Select(c => new { name = c.Key, length = c.Value.Length })
                .ToList();

            steps.Add(new { step = 3, description = "Check cookies", result = cookies });
        }

        return Results.Json(new
        {
            title = "Demo1 Logout Flow Debug",
            currentState = new { isAuthenticated = isAuthenticated },
            sessionIsolation = "Server-side via DynamicCookieService",
            steps = steps,
            nextActions = isAuthenticated ?
                new[] { "Visit /Account/Logout to test logout flow" } :
                new[] { "Visit /Account/Login to authenticate first" }
        });
    });
}

app.Run();

// Delegating handler to attach user access token (alternative to manual header set)
public class UserAccessTokenHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor = new HttpContextAccessor();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var context = _httpContextAccessor.HttpContext;
        if (context?.User?.Identity?.IsAuthenticated == true)
        {
            var token = await context.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }
        }
        return await base.SendAsync(request, cancellationToken);
    }
}
