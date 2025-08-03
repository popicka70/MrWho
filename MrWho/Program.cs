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
using MrWho.Handlers.Users;

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

// Register User management handlers
builder.Services.AddScoped<IGetUsersHandler, GetUsersHandler>();
builder.Services.AddScoped<IGetUserHandler, GetUserHandler>();
//builder.Services.AddScoped<ICreateUserHandler, CreateUserHandler>();
//builder.Services.AddScoped<IUpdateUserHandler, UpdateUserHandler>();
//builder.Services.AddScoped<IDeleteUserHandler, DeleteUserHandler>();
//builder.Services.AddScoped<IChangePasswordHandler, ChangePasswordHandler>();
//builder.Services.AddScoped<IResetPasswordHandler, ResetPasswordHandler>();
//builder.Services.AddScoped<ISetLockoutHandler, SetLockoutHandler>();

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
               .SetUserInfoEndpointUris("/connect/userinfo")

               // Enable grant types
               .AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow();

        // Register scopes (including API scopes)
        options.RegisterScopes("openid",
                              OpenIddictConstants.Scopes.Email,
                              OpenIddictConstants.Scopes.Profile,
                              OpenIddictConstants.Scopes.Roles,
                              "api.read",   // Add this
                              "api.write"); // Add this

        // Register the signing and encryption credentials
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core options
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Add authentication for API access
builder.Services.AddAuthentication()
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://localhost:7113";
        options.RequireHttpsMetadata = false; // Only for development
        options.TokenValidationParameters.ValidateAudience = false;
        options.TokenValidationParameters.ValidateIssuer = false;
    });

// Configure authorization policies
builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes("Identity.Application", "Bearer")
        .Build();
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

// Initialize database and seed essential data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();
    
    // Ensure database is created (works for both development and production)
    await context.Database.EnsureCreatedAsync();
    
    // Initialize essential data (admin realm, admin client, admin user)
    try
    {
        await oidcClientService.InitializeEssentialDataAsync();
        Console.WriteLine("Essential OIDC data initialized successfully");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error initializing essential OIDC data: {ex.Message}");
        throw;
    }
    
    // Seed additional test users for development
    if (!await context.Users.AnyAsync(u => u.UserName == "test@example.com"))
    {
        var testUser = new IdentityUser 
        { 
            UserName = "test@example.com", 
            Email = "test@example.com", 
            EmailConfirmed = true 
        };
        await userManager.CreateAsync(testUser, "Test123!");
        Console.WriteLine("Created test user");
    }
    
    // Initialize default realm and clients using the dynamic service (keeping for backwards compatibility)
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

// API Test endpoint (for debugging)
app.MapGet("/api/test", [Authorize] () =>
{
    return Results.Ok(new { Message = "API is working!", Timestamp = DateTime.UtcNow });
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

app.MapGet("/debug/admin-client-info", async (IOidcClientService oidcClientService) =>
{
    var clients = await oidcClientService.GetEnabledClientsAsync();
    var adminClient = clients.FirstOrDefault(c => c.ClientId == "mrwho_admin_web");
    
    if (adminClient == null)
    {
        return Results.NotFound("Admin client not found");
    }
    
    return Results.Ok(new
    {
        ClientId = adminClient.ClientId,
        ClientSecret = adminClient.ClientSecret,
        Name = adminClient.Name,
        RealmName = adminClient.Realm.Name,
        IsEnabled = adminClient.IsEnabled,
        AuthorizeUrl = "https://localhost:7113/connect/authorize",
        TokenUrl = "https://localhost:7113/connect/token",
        LogoutUrl = "https://localhost:7113/connect/logout",
        RedirectUris = adminClient.RedirectUris.Select(ru => ru.Uri).ToArray(),
        PostLogoutRedirectUris = adminClient.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
        Scopes = adminClient.Scopes.Select(s => s.Scope).ToArray(),
        SampleAuthUrl = $"https://localhost:7113/connect/authorize?client_id={adminClient.ClientId}&response_type=code&redirect_uri=https://localhost:7257/signin-oidc&scope=openid%20email%20profile%20roles%20api.read%20api.write&state=admin_test",
        SampleLogoutUrl = "https://localhost:7113/connect/logout?post_logout_redirect_uri=https://localhost:7257/signout-callback-oidc",
        AdminCredentials = new
        {
            Username = "admin@mrwho.local",
            Password = "MrWhoAdmin2024!"
        }
    });
});

// Debug endpoint for all essential data
app.MapGet("/debug/essential-data", async (IOidcClientService oidcClientService, ApplicationDbContext context) =>
{
    var adminRealm = await context.Realms.FirstOrDefaultAsync(r => r.Name == "admin");
    var adminClient = await context.Clients
        .Include(c => c.RedirectUris)
        .Include(c => c.PostLogoutUris)
        .Include(c => c.Scopes)
        .FirstOrDefaultAsync(c => c.ClientId == "mrwho_admin_web");
    var adminUser = await context.Users.FirstOrDefaultAsync(u => u.UserName == "admin@mrwho.local");
    
    return Results.Ok(new
    {
        AdminRealm = adminRealm != null ? new
        {
            adminRealm.Id,
            adminRealm.Name,
            adminRealm.DisplayName,
            adminRealm.Description,
            adminRealm.IsEnabled
        } : null,
        AdminClient = adminClient != null ? new
        {
            adminClient.Id,
            adminClient.ClientId,
            adminClient.Name,
            adminClient.IsEnabled,
            adminClient.RealmId,
            RedirectUris = adminClient.RedirectUris.Select(ru => ru.Uri).ToArray(),
            PostLogoutUris = adminClient.PostLogoutUris.Select(plu => plu.Uri).ToArray(),
            Scopes = adminClient.Scopes.Select(s => s.Scope).ToArray()
        } : null,
        AdminUser = adminUser != null ? new
        {
            adminUser.Id,
            adminUser.UserName,
            adminUser.Email,
            adminUser.EmailConfirmed
        } : null,
        SetupInstructions = new
        {
            LoginUrl = "https://localhost:7257/login",
            AdminCredentials = new
            {
                Username = "admin@mrwho.local",
                Password = "MrWhoAdmin2024!"
            }
        }
    });
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