using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllers(); // Add controllers for back-channel logout

// Add session support for logout notifications
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".MrWho.Demo1.Session";
});

// CRITICAL: Clear default claim mappings to preserve JWT claim names
Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

// CRITICAL: Use client-specific cookie scheme to prevent session sharing
const string demo1CookieScheme = "Demo1Cookies";

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = demo1CookieScheme; // Use client-specific scheme
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme; // CRITICAL: Set default sign-out scheme
})
.AddCookie(demo1CookieScheme, options => // Use client-specific scheme name
{
    options.Cookie.Name = ".MrWho.Demo1"; // Client-specific cookie name
    options.Cookie.Path = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(2); // Demo session timeout
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.SignInScheme = demo1CookieScheme; // CRITICAL: Use client-specific scheme
    options.Authority = "https://localhost:7113"; // MrWho OIDC Server
    options.ClientId = "mrwho_demo1";
    options.ClientSecret = "Demo1Secret2024!";
    options.ResponseType = OpenIdConnectResponseType.Code;
    
    // Scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("roles");
    options.Scope.Add("offline_access");
    
    // Save tokens for display
    options.SaveTokens = true;
    
    // Use PKCE for additional security
    options.UsePkce = true;
    
    // SSL configuration for development
    options.RequireHttpsMetadata = false; // Only for development
    
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
    
    // CRITICAL: Add comprehensive event handlers for logout debugging
    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = context =>
        {
            // Log the claims for debugging
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogDebug("Claims in ID token: {Claims}", 
                string.Join(", ", context.Principal?.Claims.Select(c => $"{c.Type}={c.Value}") ?? Array.Empty<string>()));
            return Task.CompletedTask;
        },
        
        // CRITICAL: This event is called when initiating logout to the OIDC provider
        OnRedirectToIdentityProviderForSignOut = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("?? LOGOUT STEP 1: Redirecting to identity provider for sign out");
            logger.LogInformation("   - Target logout URL: {LogoutUrl}", context.ProtocolMessage.IssuerAddress);
            logger.LogInformation("   - Post logout redirect URI: {PostLogoutUri}", context.ProtocolMessage.PostLogoutRedirectUri);
            logger.LogInformation("   - ID token hint: {HasIdToken}", !string.IsNullOrEmpty(context.ProtocolMessage.IdTokenHint));
            return Task.CompletedTask;
        },
        
        // CRITICAL: This event is called when returning from the OIDC provider after logout
        OnSignedOutCallbackRedirect = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("? LOGOUT STEP 2: OIDC logout completed, processing callback redirect");
            logger.LogInformation("   - Redirecting to: {RedirectUri}", context.Options.SignedOutRedirectUri);
            logger.LogInformation("   - Logout successful: User should no longer be authenticated");
            return Task.CompletedTask;
        },
        
        // NOTE: OnRemoteSignOut is only for remote-initiated logouts (e.g., logout from another app)
        // It's NOT called during normal client-initiated logout flows
        OnRemoteSignOut = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("?? REMOTE LOGOUT: Received remote sign out notification from OIDC provider");
            logger.LogWarning("   - This indicates logout was initiated from another application");
            return Task.CompletedTask;
        },
        
        // Add more logout-related event handlers for comprehensive debugging
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("? Authentication failed: {Error}", context.Exception?.Message);
            return Task.CompletedTask;
        },
        
        OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("? Remote failure: {Error}", context.Failure?.Message);
            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

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
        await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        
        return Results.Ok(new { Message = "Signed out from all schemes", Timestamp = DateTime.UtcNow });
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
        var isAuthenticated = context.User.Identity?.IsAuthenticated == true;
        
        if (!isAuthenticated)
        {
            return Results.Json(new 
            { 
                Error = "Not authenticated - cannot test logout flow",
                Suggestion = "Login first, then test logout"
            });
        }

        var accessToken = await context.GetTokenAsync("access_token");
        var idToken = await context.GetTokenAsync("id_token");
        
        return Results.Json(new
        {
            CurrentState = new
            {
                IsAuthenticated = isAuthenticated,
                UserName = context.User.Identity?.Name,
                AuthenticationType = context.User.Identity?.AuthenticationType,
                HasAccessToken = !string.IsNullOrEmpty(accessToken),
                HasIdToken = !string.IsNullOrEmpty(idToken),
                ClaimsCount = context.User.Claims.Count()
            },
            LogoutFlow = new
            {
                Step1 = "Click logout button -> calls /Account/Logout",
                Step2 = "SignOut() redirects to OIDC provider -> OnRedirectToIdentityProviderForSignOut fires",
                Step3 = "OIDC provider processes logout -> clears server session",
                Step4 = "OIDC provider redirects back -> OnSignedOutCallbackRedirect fires",
                Step5 = "User lands on home page -> should no longer be authenticated"
            },
            TestActions = new
            {
                StandardLogout = "/Account/Logout",
                DebugLogout = "/debug/logout",
                ForceClear = "/debug/logout (POST method)"
            }
        });
    });
}

app.Run();
