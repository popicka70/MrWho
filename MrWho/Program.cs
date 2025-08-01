using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container
builder.Services.AddControllersWithViews();

// Add antiforgery services
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.SuppressXFrameOptionsHeader = false;
});

// Configure Entity Framework with SQL Server (via Aspire)
builder.AddSqlServerDbContext<ApplicationDbContext>("mrwhodb", null, optionsBuilder =>
{
    optionsBuilder.UseOpenIddict();
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

// Register custom services
builder.Services.AddScoped<IOidcClientService, OidcClientService>();
builder.Services.AddScoped<ISeedingService, SeedingService>();

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

app.MapDefaultEndpoints();

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

// Initialize database and seed data using the new dynamic approach
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();
    
    // Ensure database is created (works for both development and production)
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
    
    // Initialize default realm and clients using the dynamic service
    try
    {
        await oidcClientService.InitializeDefaultRealmAndClientsAsync();
        Console.WriteLine("Dynamic OIDC client configuration initialized successfully");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error initializing dynamic OIDC client configuration: {ex.Message}");
        throw;
    }
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

app.MapGet("/debug/client-info", async (IOidcClientService oidcClientService) =>
{
    var clients = await oidcClientService.GetEnabledClientsAsync();
    var postmanClient = clients.FirstOrDefault(c => c.ClientId == "postman_client");
    
    if (postmanClient == null)
    {
        return Results.NotFound("Postman client not found");
    }
    
    return Results.Ok(new
    {
        ClientId = postmanClient.ClientId,
        ClientSecret = postmanClient.ClientSecret,
        AuthorizeUrl = "https://localhost:7000/connect/authorize",
        TokenUrl = "https://localhost:7000/connect/token",
        LogoutUrl = "https://localhost:7000/connect/logout",
        RedirectUris = postmanClient.RedirectUris.Select(ru => ru.Uri).ToArray(),
        PostLogoutRedirectUris = postmanClient.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
        SampleAuthUrl = $"https://localhost:7000/connect/authorize?client_id={postmanClient.ClientId}&response_type=code&redirect_uri=https://localhost:7002/signin-oidc&scope=openid%20email%20profile&state=test_state",
        SampleLogoutUrl = "https://localhost:7000/connect/logout?post_logout_redirect_uri=https://localhost:7002/signout-callback-oidc"
    });
});

// Debug endpoint to show actual database client configuration
app.MapGet("/debug/db-client-config", async (IOpenIddictApplicationManager applicationManager, IOidcClientService oidcClientService) =>
{
    var clients = await oidcClientService.GetEnabledClientsAsync();
    var clientConfigs = new List<object>();
    
    foreach (var client in clients)
    {
        var openIddictClient = await applicationManager.FindByClientIdAsync(client.ClientId);
        if (openIddictClient != null)
        {
            clientConfigs.Add(new
            {
                ClientId = await applicationManager.GetClientIdAsync(openIddictClient),
                DisplayName = await applicationManager.GetDisplayNameAsync(openIddictClient),
                RedirectUris = await applicationManager.GetRedirectUrisAsync(openIddictClient),
                PostLogoutRedirectUris = await applicationManager.GetPostLogoutRedirectUrisAsync(openIddictClient),
                DatabaseConfiguration = new
                {
                    client.ClientId,
                    client.Name,
                    client.IsEnabled,
                    RealmName = client.Realm.Name,
                    client.AllowAuthorizationCodeFlow,
                    client.AllowClientCredentialsFlow,
                    client.AllowPasswordFlow,
                    client.AllowRefreshTokenFlow
                }
            });
        }
    }
    
    return Results.Ok(clientConfigs);
});

app.Run();

// ================================
// DTOs AND MODELS (keeping existing for compatibility)
// ================================

public class UserDto
{
    public string Id { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailConfirmed { get; set; }
    public string? PhoneNumber { get; set; }
    public bool PhoneNumberConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool LockoutEnabled { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public int AccessFailedCount { get; set; }
}

public class CreateUserRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string UserName { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    public string Password { get; set; } = string.Empty;

    public string? PhoneNumber { get; set; }
    public bool? EmailConfirmed { get; set; }
    public bool? PhoneNumberConfirmed { get; set; }
    public bool? TwoFactorEnabled { get; set; }
}

public class UpdateUserRequest
{
    [EmailAddress]
    public string? Email { get; set; }

    public string? UserName { get; set; }
    public string? PhoneNumber { get; set; }
    public bool? EmailConfirmed { get; set; }
    public bool? PhoneNumberConfirmed { get; set; }
    public bool? TwoFactorEnabled { get; set; }
}

public class ChangePasswordRequest
{
    [Required]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    public string NewPassword { get; set; } = string.Empty;
}

public class ResetPasswordRequest
{
    [Required]
    [MinLength(6)]
    public string NewPassword { get; set; } = string.Empty;
}

public class SetLockoutRequest
{
    public DateTimeOffset? LockoutEnd { get; set; }
}

public class PagedResult<T>
{
    public List<T> Items { get; set; } = new();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }
}

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