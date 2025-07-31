using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Data;
using MrWho.Handlers;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews();

// Add antiforgery services
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.SuppressXFrameOptionsHeader = false;
});

// Configure Entity Framework with SQLite (persistent database)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite("Data Source=MrWho.db");
    options.UseOpenIddict();
});

// Configure Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure Identity options
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    
    // Configure Claims Identity to work with OpenIddict claims
    options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
    options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
    options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
});

// Register token handler
builder.Services.AddScoped<ITokenHandler, MrWho.Handlers.TokenHandler>();

// Register userinfo handler
builder.Services.AddScoped<IUserInfoHandler, MrWho.Handlers.UserInfoHandler>();

// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        // Enable the authorization and token endpoints
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetEndSessionEndpointUris("/connect/logout")
               .SetConfigurationEndpointUris("/.well-known/openid_configuration")

               // Enable grant types
               .AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow();

        // Register scopes
        options.RegisterScopes("openid",
                              OpenIddictConstants.Scopes.Email,
                              OpenIddictConstants.Scopes.Profile,
                              OpenIddictConstants.Scopes.Roles);

        // Register the signing and encryption credentials
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core options
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Add antiforgery middleware
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

// Initialize database and seed data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    
    await context.Database.EnsureCreatedAsync();
    
    // Seed test users
    if (!context.Users.Any())
    {
        var user1 = new IdentityUser 
        { 
            UserName = "test@example.com", 
            Email = "test@example.com", 
            EmailConfirmed = true 
        };
        await userManager.CreateAsync(user1, "Test123!");
        
        var user2 = new IdentityUser 
        { 
            UserName = "admin@example.com", 
            Email = "admin@example.com", 
            EmailConfirmed = true 
        };
        await userManager.CreateAsync(user2, "Admin123!");
    }
    
    // Seed OpenIddict applications for testing
    var existingClient = await applicationManager.FindByClientIdAsync("postman_client");
    if (existingClient != null)
    {
        // Update existing client with new redirect URIs
        await applicationManager.DeleteAsync(existingClient);
    }
    
    // Create or recreate the client with updated configuration
    await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
    {
        ClientId = "postman_client",
        ClientSecret = "postman_secret",
        DisplayName = "Postman Test Client",
        Permissions =
        {
            OpenIddictConstants.Permissions.Endpoints.Authorization,
            OpenIddictConstants.Permissions.Endpoints.Token,
            OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
            OpenIddictConstants.Permissions.GrantTypes.Password,
            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
            "oidc:scope:openid",
            OpenIddictConstants.Permissions.Scopes.Email,
            OpenIddictConstants.Permissions.Scopes.Profile,
            OpenIddictConstants.Permissions.Scopes.Roles,
            OpenIddictConstants.Permissions.ResponseTypes.Code
        },
        RedirectUris = { 
            new Uri("https://localhost:7001/callback"), 
            new Uri("http://localhost:5001/callback"),

            // Comprehensive localhost:7002 redirect URIs
            new Uri("https://localhost:7002/"),
            new Uri("https://localhost:7002/callback"),
            new Uri("https://localhost:7002/signin-oidc"),
            new Uri("https://localhost:7002/auth/callback"),
            new Uri("https://localhost:7002/authentication/callback"),
            new Uri("https://localhost:7002/oidc/callback"),
            new Uri("https://localhost:7002/oauth/callback"),
            new Uri("https://localhost:7002/login/callback"),
            new Uri("https://localhost:7002/account/callback"),
            new Uri("https://localhost:7002/signin"),
            new Uri("https://localhost:7002/login"),
            new Uri("https://localhost:7002/auth"),
            new Uri("https://localhost:7002/connect/callback")
        },
        PostLogoutRedirectUris = { 
            new Uri("https://localhost:7001/"), 
            new Uri("http://localhost:5001/"),

            // Comprehensive localhost:7002 post-logout redirect URIs
            new Uri("https://localhost:7002/"),
            new Uri("https://localhost:7002/signout-callback-oidc"),
            new Uri("https://localhost:7002/logout"),
            new Uri("https://localhost:7002/signout"),
            new Uri("https://localhost:7002/auth/logout"),
            new Uri("https://localhost:7002/authentication/logout"),
            new Uri("https://localhost:7002/oidc/logout"),
            new Uri("https://localhost:7002/oauth/logout"),
            new Uri("https://localhost:7002/account/logout"),
            new Uri("https://localhost:7002/connect/logout")
        }
    });
}

// Configure routing for controllers
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// OIDC Token endpoint - now uses injected TokenHandler
app.MapPost("/connect/token", async (HttpContext context, ITokenHandler tokenHandler) =>
{
    return await tokenHandler.HandleTokenRequestAsync(context);
});

// UserInfo endpoint (optional but recommended)
app.MapGet("/connect/userinfo", [Authorize] async (HttpContext context, IUserInfoHandler userInfoHandler) =>
{
    return await userInfoHandler.HandleUserInfoRequestAsync(context);
});

app.MapGet("/debug/client-info", () => new
{
    ClientId = "postman_client",
    ClientSecret = "postman_secret", 
    AuthorizeUrl = "https://localhost:7000/connect/authorize",
    TokenUrl = "https://localhost:7000/connect/token",
    LogoutUrl = "https://localhost:7000/connect/logout",
    RedirectUris = new[]
    {
        "https://localhost:7001/callback",
        "http://localhost:5001/callback", 
        "https://localhost:7002/callback",
        "https://localhost:7002/signin-oidc"
    },
    PostLogoutRedirectUris = new[]
    {
        "https://localhost:7001/",
        "http://localhost:5001/",
        "https://localhost:7002/",
        "https://localhost:7002/signout-callback-oidc"
    },
    SampleAuthUrl = "https://localhost:7000/connect/authorize?client_id=postman_client&response_type=code&redirect_uri=https://localhost:7002/signin-oidc&scope=openid%20email%20profile&state=test_state",
    SampleLogoutUrl = "https://localhost:7000/connect/logout?post_logout_redirect_uri=https://localhost:7002/signout-callback-oidc"
});

// Debug endpoint to show actual database client configuration
app.MapGet("/debug/db-client-config", async (IOpenIddictApplicationManager applicationManager) =>
{
    var client = await applicationManager.FindByClientIdAsync("postman_client");
    if (client == null) return Results.NotFound("Client not found");
    
    return Results.Ok(new
    {
        ClientId = await applicationManager.GetClientIdAsync(client),
        DisplayName = await applicationManager.GetDisplayNameAsync(client),
        RedirectUris = await applicationManager.GetRedirectUrisAsync(client),
        PostLogoutRedirectUris = await applicationManager.GetPostLogoutRedirectUrisAsync(client)
    });
});

app.Run();

/// <summary>
/// Static class to handle token endpoint requests
/// </summary>
public static class TokenHandler
{
    /// <summary>
    /// Handles token requests including password and client credentials grant types
    /// </summary>
    public static async Task<IResult> HandleTokenRequest(HttpContext context)
    {
        var request = context.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsPasswordGrantType())
        {
            return await HandlePasswordGrantAsync(context, request);
        }

        if (request.IsClientCredentialsGrantType())
        {
            return HandleClientCredentialsGrant(request);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private static async Task<IResult> HandlePasswordGrantAsync(HttpContext context, OpenIddictRequest request)
    {
        var userManager = context.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
        var user = await userManager.FindByNameAsync(request.Username!);

        if (user != null && await userManager.CheckPasswordAsync(user, request.Password!))
        {
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
            identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email!);
            identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName!);
            identity.AddClaim(OpenIddictConstants.Claims.PreferredUsername, user.UserName!);

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Results.Forbid(authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    private static IResult HandleClientCredentialsGrant(OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId!);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(request.GetScopes());

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}