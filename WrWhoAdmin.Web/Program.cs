using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MrWhoAdmin.Web;
using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Services;
using Radzen;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOutputCache();

// Add Radzen services
builder.Services.AddRadzenComponents();
builder.Services.AddScoped<DialogService>();
builder.Services.AddScoped<NotificationService>();
builder.Services.AddScoped<TooltipService>();
builder.Services.AddScoped<ContextMenuService>();

// Add HTTP context accessor for authentication handler
builder.Services.AddHttpContextAccessor();

// Add authentication delegating handler
builder.Services.AddTransient<AuthenticationDelegatingHandler>();

// Get the MrWho API base URL from configuration
var mrWhoApiBaseUrl = builder.Configuration.GetValue<string>("MrWhoApi:BaseUrl") ?? "https://localhost:7113/";

// Register MrWho API clients with authentication
builder.Services.AddHttpClient<IRealmsApiService, RealmsApiService>(client =>
{
    client.BaseAddress = new Uri(mrWhoApiBaseUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.Timeout = TimeSpan.FromSeconds(30);
})
.AddHttpMessageHandler<AuthenticationDelegatingHandler>();

builder.Services.AddHttpClient<IClientsApiService, ClientsApiService>(client =>
{
    client.BaseAddress = new Uri(mrWhoApiBaseUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.Timeout = TimeSpan.FromSeconds(30);
})
.AddHttpMessageHandler<AuthenticationDelegatingHandler>();

builder.Services.AddHttpClient<IUsersApiService, UsersApiService>(client =>
{
    client.BaseAddress = new Uri(mrWhoApiBaseUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.Timeout = TimeSpan.FromSeconds(30);
})
.AddHttpMessageHandler<AuthenticationDelegatingHandler>();

// Add Authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Get values from configuration
    var authConfig = builder.Configuration.GetSection("Authentication");
    
    options.Authority = authConfig.GetValue<string>("Authority") ?? "https://localhost:7113/";
    options.ClientId = authConfig.GetValue<string>("ClientId") ?? "mrwho_admin_web";
    options.ClientSecret = authConfig.GetValue<string>("ClientSecret") ?? "MrWhoAdmin2024!SecretKey";
    
    options.ResponseType = "code";
    options.SaveTokens = true; // CRITICAL: This saves tokens for API calls
    options.GetClaimsFromUserInfoEndpoint = true;
    options.RequireHttpsMetadata = false; // Only for development

    // Set explicit callback paths for the admin web app (port 7257)
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-callback-oidc";

    // Additional configuration for OpenIddict compatibility
    options.MetadataAddress = $"{options.Authority}.well-known/openid_configuration";
    options.UsePkce = true; // Enable PKCE for better security

    // Map standard OIDC scopes + API scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("roles");
    options.Scope.Add("api.read");  // Add API read scope
    options.Scope.Add("api.write"); // Add API write scope

    // Force UserInfo endpoint call by removing ALL claims from ID token processing
    options.ClaimActions.Clear();
    options.ClaimActions.DeleteClaim("iss");
    options.ClaimActions.DeleteClaim("aud");
    options.ClaimActions.DeleteClaim("exp");
    options.ClaimActions.DeleteClaim("iat");
    options.ClaimActions.DeleteClaim("nonce");
    options.ClaimActions.DeleteClaim("at_hash");
    options.ClaimActions.DeleteClaim("azp");
    options.ClaimActions.DeleteClaim("oi_au_id");
    options.ClaimActions.DeleteClaim("oi_tbn_id");

    // Only map claims from UserInfo endpoint
    options.ClaimActions.MapJsonKey("name", "name");
    options.ClaimActions.MapJsonKey("given_name", "given_name");
    options.ClaimActions.MapJsonKey("family_name", "family_name");
    options.ClaimActions.MapJsonKey("email", "email");

    // Event logging for debugging
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Redirecting to identity provider: {Authority}", options.Authority);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token validated successfully");
            return Task.CompletedTask;
        },
        OnTokenResponseReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token response received - Access Token: {HasAccessToken}, Refresh Token: {HasRefreshToken}", 
                !string.IsNullOrEmpty(context.TokenEndpointResponse.AccessToken),
                !string.IsNullOrEmpty(context.TokenEndpointResponse.RefreshToken));
            return Task.CompletedTask;
        },
        OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("Remote authentication failure: {Error}", context.Failure?.Message);
            return Task.CompletedTask;
        }
    };
});

// Add Authorization services
builder.Services.AddAuthorization();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

// Map authentication endpoints
app.MapGet("/login", async (HttpContext context, string? returnUrl = null) =>
{
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme,
        new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? "/"
        });
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});

app.UseOutputCache();

app.MapStaticAssets();

// Configure Blazor components properly
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddAdditionalAssemblies(typeof(Radzen.Blazor.RadzenButton).Assembly);

app.MapDefaultEndpoints();

app.Run();

/// <summary>
/// Delegating handler to add authentication token to API requests
/// </summary>
public class AuthenticationDelegatingHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthenticationDelegatingHandler> _logger;

    public AuthenticationDelegatingHandler(IHttpContextAccessor httpContextAccessor, ILogger<AuthenticationDelegatingHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            try
            {
                var accessToken = await httpContext.GetTokenAsync("access_token");
                if (!string.IsNullOrEmpty(accessToken))
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                    _logger.LogDebug("Added Bearer token to request: {RequestUri} (Token preview: {TokenPreview})", 
                        request.RequestUri, accessToken.Substring(0, Math.Min(20, accessToken.Length)) + "...");
                }
                else
                {
                    _logger.LogWarning("No access token found for authenticated user - checking available tokens");
                    
                    // Log available token names for debugging
                    var tokens = await httpContext.GetTokenAsync("id_token");
                    _logger.LogDebug("Available tokens - ID Token: {HasIdToken}", !string.IsNullOrEmpty(tokens));
                    
                    var refreshToken = await httpContext.GetTokenAsync("refresh_token");
                    _logger.LogDebug("Available tokens - Refresh Token: {HasRefreshToken}", !string.IsNullOrEmpty(refreshToken));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting access token for request to {RequestUri}", request.RequestUri);
            }
        }
        else
        {
            _logger.LogDebug("User not authenticated, skipping token attachment for: {RequestUri}", request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
