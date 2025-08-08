using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container.
builder.Services.AddRazorPages();

// CRITICAL: Clear default claim mappings to preserve JWT claim names
Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
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
    
    // Optional: Add event handlers for debugging
    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = context =>
        {
            // Log the claims for debugging
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogDebug("Claims in ID token: {Claims}", 
                string.Join(", ", context.Principal?.Claims.Select(c => $"{c.Type}={c.Value}") ?? Array.Empty<string>()));
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

// Add authentication middleware
app.UseAuthentication();
app.UseAuthorization();

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

app.Run();
