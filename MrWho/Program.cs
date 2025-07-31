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

// Initialize database and seed data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    
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
    
    // Seed OpenIddict applications for testing
    try
    {
        // Clear all existing clients to ensure clean state
        var existingClient = await applicationManager.FindByClientIdAsync("postman_client");
        if (existingClient != null)
        {
            await applicationManager.DeleteAsync(existingClient);
        }
        
        // Create fresh client with complete configuration
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "postman_client",
            ClientSecret = "postman_secret",
            DisplayName = "Postman Test Client",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                "oidc:scope:openid",
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            }
        };

        // Add redirect URIs
        descriptor.RedirectUris.Add(new Uri("https://localhost:7001/callback"));
        descriptor.RedirectUris.Add(new Uri("http://localhost:5001/callback"));
        descriptor.RedirectUris.Add(new Uri("https://localhost:7002/"));
        descriptor.RedirectUris.Add(new Uri("https://localhost:7002/callback"));
        descriptor.RedirectUris.Add(new Uri("https://localhost:7002/signin-oidc"));
        descriptor.RedirectUris.Add(new Uri("https://localhost:7257/"));
        descriptor.RedirectUris.Add(new Uri("https://localhost:7257/callback"));
        descriptor.RedirectUris.Add(new Uri("https://localhost:7257/signin-oidc"));

        // Add post-logout redirect URIs
        descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:7001/"));
        descriptor.PostLogoutRedirectUris.Add(new Uri("http://localhost:5001/"));
        descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:7002/"));
        descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:7002/signout-callback-oidc"));
        descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:7257/"));
        descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:7257/signout-callback-oidc"));

        await applicationManager.CreateAsync(descriptor);
        Console.WriteLine("OpenIddict client created successfully with EndSession permission and post-logout URIs");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error setting up OpenIddict client: {ex.Message}");
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

// ================================
// USERS CRUD API ENDPOINTS
// =================??===============

// Get all users with pagination
app.MapGet("/api/users", [Authorize] async (
    [FromQuery] int page,
    [FromQuery] int pageSize,
    [FromQuery] string? search,
    UserManager<IdentityUser> userManager) =>
{
    if (page < 1) page = 1;
    if (pageSize < 1 || pageSize > 100) pageSize = 10;

    var query = userManager.Users.AsQueryable();

    if (!string.IsNullOrWhiteSpace(search))
    {
        query = query.Where(u => u.UserName!.Contains(search) || u.Email!.Contains(search));
    }

    var totalCount = await query.CountAsync();
    var users = await query
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .Select(u => new UserDto
        {
            Id = u.Id,
            UserName = u.UserName!,
            Email = u.Email!,
            EmailConfirmed = u.EmailConfirmed,
            PhoneNumber = u.PhoneNumber,
            PhoneNumberConfirmed = u.PhoneNumberConfirmed,
            TwoFactorEnabled = u.TwoFactorEnabled,
            LockoutEnabled = u.LockoutEnabled,
            LockoutEnd = u.LockoutEnd,
            AccessFailedCount = u.AccessFailedCount
        })
        .ToListAsync();

    var result = new PagedResult<UserDto>
    {
        Items = users,
        TotalCount = totalCount,
        Page = page,
        PageSize = pageSize,
        TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
    };

    return Results.Ok(result);
});

// Get user by ID
app.MapGet("/api/users/{id}", [Authorize] async (string id, UserManager<IdentityUser> userManager) =>
{
    var user = await userManager.FindByIdAsync(id);
    if (user == null)
    {
        return Results.NotFound($"User with ID '{id}' not found.");
    }

    var userDto = new UserDto
    {
        Id = user.Id,
        UserName = user.UserName!,
        Email = user.Email!,
        EmailConfirmed = user.EmailConfirmed,
        PhoneNumber = user.PhoneNumber,
        PhoneNumberConfirmed = user.PhoneNumberConfirmed,
        TwoFactorEnabled = user.TwoFactorEnabled,
        LockoutEnabled = user.LockoutEnabled,
        LockoutEnd = user.LockoutEnd,
        AccessFailedCount = user.AccessFailedCount
    };

    return Results.Ok(userDto);
});

// Create new user
app.MapPost("/api/users", [Authorize] async (CreateUserRequest request, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
{
    var user = new IdentityUser
    {
        UserName = request.UserName,
        Email = request.Email,
        EmailConfirmed = request.EmailConfirmed ?? false,
        PhoneNumber = request.PhoneNumber,
        PhoneNumberConfirmed = request.PhoneNumberConfirmed ?? false,
        TwoFactorEnabled = request.TwoFactorEnabled ?? false
    };

    var result = await userManager.CreateAsync(user, request.Password);

    if (!result.Succeeded)
    {
        var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
        return Results.BadRequest(new { errors });
    }

    logger.LogInformation("User {UserName} created successfully with ID {UserId}", user.UserName, user.Id);

    var userDto = new UserDto
    {
        Id = user.Id,
        UserName = user.UserName,
        Email = user.Email,
        EmailConfirmed = user.EmailConfirmed,
        PhoneNumber = user.PhoneNumber,
        PhoneNumberConfirmed = user.PhoneNumberConfirmed,
        TwoFactorEnabled = user.TwoFactorEnabled,
        LockoutEnabled = user.LockoutEnabled,
        LockoutEnd = user.LockoutEnd,
        AccessFailedCount = user.AccessFailedCount
    };

    return Results.Created($"/api/users/{user.Id}", userDto);
});

// Update user
app.MapPut("/api/users/{id}", [Authorize] async (string id, UpdateUserRequest request, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
{
    var user = await userManager.FindByIdAsync(id);
    if (user == null)
    {
        return Results.NotFound($"User with ID '{id}' not found.");
    }

    // Update user properties
    user.UserName = request.UserName ?? user.UserName;
    user.Email = request.Email ?? user.Email;
    user.PhoneNumber = request.PhoneNumber;
    
    if (request.EmailConfirmed.HasValue)
        user.EmailConfirmed = request.EmailConfirmed.Value;
    
    if (request.PhoneNumberConfirmed.HasValue)
        user.PhoneNumberConfirmed = request.PhoneNumberConfirmed.Value;
    
    if (request.TwoFactorEnabled.HasValue)
        user.TwoFactorEnabled = request.TwoFactorEnabled.Value;

    var result = await userManager.UpdateAsync(user);

    if (!result.Succeeded)
    {
        var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
        return Results.BadRequest(new { errors });
    }

    logger.LogInformation("User {UserName} updated successfully", user.UserName);

    var userDto = new UserDto
    {
        Id = user.Id,
        UserName = user.UserName,
        Email = user.Email,
        EmailConfirmed = user.EmailConfirmed,
        PhoneNumber = user.PhoneNumber,
        PhoneNumberConfirmed = user.PhoneNumberConfirmed,
        TwoFactorEnabled = user.TwoFactorEnabled,
        LockoutEnabled = user.LockoutEnabled,
        LockoutEnd = user.LockoutEnd,
        AccessFailedCount = user.AccessFailedCount
    };

    return Results.Ok(userDto);
});

// Delete user
app.MapDelete("/api/users/{id}", [Authorize] async (string id, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
{
    var user = await userManager.FindByIdAsync(id);
    if (user == null)
    {
        return Results.NotFound($"User with ID '{id}' not found.");
    }

    var result = await userManager.DeleteAsync(user);

    if (!result.Succeeded)
    {
        var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
        return Results.BadRequest(new { errors });
    }

    logger.LogInformation("User {UserName} deleted successfully", user.UserName);

    return Results.NoContent();
});

// Change user password
app.MapPost("/api/users/{id}/change-password", [Authorize] async (string id, ChangePasswordRequest request, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
{
    var user = await userManager.FindByIdAsync(id);
    if (user == null)
    {
        return Results.NotFound($"User with ID '{id}' not found.");
    }

    var result = await userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);

    if (!result.Succeeded)
    {
        var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
        return Results.BadRequest(new { errors });
    }

    logger.LogInformation("Password changed successfully for user {UserName}", user.UserName);

    return Results.Ok(new { message = "Password changed successfully" });
});

// Reset user password (admin function)
app.MapPost("/api/users/{id}/reset-password", [Authorize] async (string id, ResetPasswordRequest request, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
{
    var user = await userManager.FindByIdAsync(id);
    if (user == null)
    {
        return Results.NotFound($"User with ID '{id}' not found.");
    }

    var token = await userManager.GeneratePasswordResetTokenAsync(user);
    var result = await userManager.ResetPasswordAsync(user, token, request.NewPassword);

    if (!result.Succeeded)
    {
        var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
        return Results.BadRequest(new { errors });
    }

    logger.LogInformation("Password reset successfully for user {UserName}", user.UserName);

    return Results.Ok(new { message = "Password reset successfully" });
});

// Lock/unlock user account
app.MapPost("/api/users/{id}/lockout", [Authorize] async (string id, SetLockoutRequest request, UserManager<IdentityUser> userManager, ILogger<Program> logger) =>
{
    var user = await userManager.FindByIdAsync(id);
    if (user == null)
    {
        return Results.NotFound($"User with ID '{id}' not found.");
    }

    var result = await userManager.SetLockoutEndDateAsync(user, request.LockoutEnd);

    if (!result.Succeeded)
    {
        var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
        return Results.BadRequest(new { errors });
    }

    var action = request.LockoutEnd.HasValue && request.LockoutEnd > DateTimeOffset.UtcNow ? "locked" : "unlocked";
    logger.LogInformation("User {UserName} {Action} successfully", user.UserName, action);

    return Results.Ok(new { message = $"User {action} successfully" });
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

// ================================
// DTOs AND MODELS
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