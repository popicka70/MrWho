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

// Add HTTP context accessor for authentication handler
builder.Services.AddHttpContextAccessor();

// Add HTTP clients for APIs
builder.Services.AddHttpClient<WeatherApiClient>(client =>
    {
        // This URL uses "https+http://" to indicate HTTPS is preferred over HTTP.
        // Learn more about service discovery scheme resolution at https://aka.ms/dotnet/sdschemes.
        client.BaseAddress = new("https+http://apiservice");
    });

// Add MrWho API clients with authentication
builder.Services.AddHttpClient<IRealmsApiService, RealmsApiService>("MrWhoApi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7113/"); // MrWho API base URL
    client.DefaultRequestHeaders.Add("Accept", "application/json");
})
.AddHttpMessageHandler<AuthenticationDelegatingHandler>();

builder.Services.AddHttpClient<IClientsApiService, ClientsApiService>("MrWhoApi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7113/");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
})
.AddHttpMessageHandler<AuthenticationDelegatingHandler>();

builder.Services.AddHttpClient<IUsersApiService, UsersApiService>("MrWhoApi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7113/");
    client.DefaultRequestHeaders.Add("Accept", "application/json");
})
.AddHttpMessageHandler<AuthenticationDelegatingHandler>();

// Register API services
builder.Services.AddScoped<IRealmsApiService, RealmsApiService>();
builder.Services.AddScoped<IClientsApiService, ClientsApiService>();
builder.Services.AddScoped<IUsersApiService, UsersApiService>();

// Add authentication delegating handler
builder.Services.AddTransient<AuthenticationDelegatingHandler>();

// Add Authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Use the dedicated admin client created by the seeding process
    options.Authority = "https://localhost:7113/";
    options.ClientId = "mrwho_admin_web";
    options.ClientSecret = "MrWhoAdmin2024!SecretKey";
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.RequireHttpsMetadata = false; // Only for development

    // Set explicit callback paths for the admin web app (port 7257)
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-callback-oidc";

    // Additional configuration for OpenIddict compatibility
    options.MetadataAddress = "https://localhost:7113/.well-known/openid_configuration";
    options.UsePkce = true; // Enable PKCE for better security

    // Map standard OIDC scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("roles");

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
    options.ClaimActions.DeleteClaim("oi_tnk_id");

    // Only map claims from UserInfo endpoint
    options.ClaimActions.MapJsonKey("name", "name");
    options.ClaimActions.MapJsonKey("given_name", "given_name");
    options.ClaimActions.MapJsonKey("family_name", "family_name");
    options.ClaimActions.MapJsonKey("email", "email");

    // Comprehensive event logging for debugging
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Redirecting to identity provider: {Authority}", context.ProtocolMessage.IssuerAddress);
            logger.LogInformation("Client ID: {ClientId}", context.ProtocolMessage.ClientId);
            logger.LogInformation("Redirect URI: {RedirectUri}", context.ProtocolMessage.RedirectUri);
            logger.LogInformation("Response Type: {ResponseType}", context.ProtocolMessage.ResponseType);
            logger.LogInformation("Scope: {Scope}", context.ProtocolMessage.Scope);
            logger.LogInformation("State: {State}", context.ProtocolMessage.State);
            return Task.CompletedTask;
        },
        OnAuthorizationCodeReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Authorization code received from identity provider");
            logger.LogInformation("Code: {Code}", context.ProtocolMessage.Code?.Substring(0, Math.Min(10, context.ProtocolMessage.Code.Length)) + "...");
            return Task.CompletedTask;
        },
        OnTokenResponseReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token response received from identity provider");
            logger.LogInformation("Access token present: {HasAccessToken}", !string.IsNullOrEmpty(context.TokenEndpointResponse.AccessToken));
            logger.LogInformation("Refresh token present: {HasRefreshToken}", !string.IsNullOrEmpty(context.TokenEndpointResponse.RefreshToken));
            logger.LogInformation("ID token present: {HasIdToken}", !string.IsNullOrEmpty(context.TokenEndpointResponse.IdToken));
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token validated successfully. Will call UserInfo endpoint: {GetClaimsFromUserInfoEndpoint}", context.Options.GetClaimsFromUserInfoEndpoint);

            // Log all claims from ID token for debugging
            logger.LogInformation("=== Claims from ID Token ===");
            foreach (var claim in context.Principal?.Claims ?? [])
            {
                logger.LogInformation("ID Token Claim: {Type} = {Value}", claim.Type, claim.Value);
            }
            logger.LogInformation("=== End ID Token Claims ===");

            return Task.CompletedTask;
        },
        OnUserInformationReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("!!! UserInfo endpoint was called !!!");
            logger.LogInformation("User information received from UserInfo endpoint: {UserInfo}", context.User.ToString());
            return Task.CompletedTask;
        },
        OnTicketReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Final authentication ticket received");

            // Log final claims after all processing
            logger.LogInformation("=== Final Claims in Authentication Ticket ===");
            foreach (var claim in context.Principal?.Claims ?? [])
            {
                logger.LogInformation("Final Claim: {Type} = {Value}", claim.Type, claim.Value);
            }
            logger.LogInformation("=== End Final Claims ===");

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

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapDefaultEndpoints();

app.Run();

/// <summary>
/// Delegating handler to add authentication token to API requests
/// </summary>
public class AuthenticationDelegatingHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthenticationDelegatingHandler(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext?.User.Identity?.IsAuthenticated == true)
        {
            var accessToken = await httpContext.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            }
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
