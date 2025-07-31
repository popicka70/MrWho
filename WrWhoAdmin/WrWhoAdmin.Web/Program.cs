using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using WrWhoAdmin.Web;
using WrWhoAdmin.Web.Components;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOutputCache();

builder.Services.AddHttpClient<WeatherApiClient>(client =>
    {
        // This URL uses "https+http://" to indicate HTTPS is preferred over HTTP.
        // Learn more about service discovery scheme resolution at https://aka.ms/dotnet/sdschemes.
        client.BaseAddress = new("https+http://apiservice");
    });

// Add Authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = "https://localhost:7113/";
    options.ClientId = "postman_client";
    options.ClientSecret = "postman_secret";
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.RequireHttpsMetadata = false; // Only for development

    // Set explicit callback paths based on your app's URL
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
    options.ClaimActions.DeleteClaim("oi_tkn_id");

    // Only map claims from UserInfo endpoint
    options.ClaimActions.MapJsonKey("name", "name");
    options.ClaimActions.MapJsonKey("given_name", "given_name");
    options.ClaimActions.MapJsonKey("family_name", "family_name");
    options.ClaimActions.MapJsonKey("email", "email");
    options.ClaimActions.MapJsonKey("preferred_username", "preferred_username");

    // Add events for debugging
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            // Log the redirect URL for debugging
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Redirecting to identity provider: {RedirectUri}", context.ProtocolMessage.RedirectUri);
            logger.LogInformation("Client ID being sent: {ClientId}", context.ProtocolMessage.ClientId);
            logger.LogInformation("Full authorization URL: {AuthorizationEndpoint}", context.ProtocolMessage.BuildRedirectUrl());
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError(context.Exception, "Authentication failed: {Error}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnAuthorizationCodeReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Authorization code received, about to exchange for tokens");
            return Task.CompletedTask;
        },
        OnTokenResponseReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token response received. Access token present: {HasAccessToken}", !string.IsNullOrEmpty(context.TokenEndpointResponse.AccessToken));
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
