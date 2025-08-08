using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Handlers.Users;
using MrWho.Services;
using MrWho.Shared;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MrWho.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoServices(this IServiceCollection services)
    {
        // Register custom services
        services.AddScoped<IOidcClientService, OidcClientService>();
        services.AddScoped<ISeedingService, SeedingService>();
        services.AddScoped<IScopeSeederService, ScopeSeederService>();
        services.AddScoped<IOpenIddictScopeSyncService, OpenIddictScopeSyncService>();
        services.AddScoped<IApiResourceSeederService, ApiResourceSeederService>();
        services.AddScoped<IIdentityResourceSeederService, IdentityResourceSeederService>();

        // Register token handler
        services.AddScoped<ITokenHandler, TokenHandler>();

        // Register authorization handler
        services.AddScoped<IOidcAuthorizationHandler, OidcAuthorizationHandler>();

        // Register userinfo handler
        services.AddScoped<IUserInfoHandler, UserInfoHandler>();

        // Register User management handlers
        services.AddScoped<IGetUsersHandler, GetUsersHandler>();
        services.AddScoped<IGetUserHandler, GetUserHandler>();
        services.AddScoped<ICreateUserHandler, CreateUserHandler>();
        services.AddScoped<IUpdateUserHandler, UpdateUserHandler>();
        services.AddScoped<IDeleteUserHandler, DeleteUserHandler>();
        //services.AddScoped<IChangePasswordHandler, ChangePasswordHandler>();
        //services.AddScoped<IResetPasswordHandler, ResetPasswordHandler>();
        //services.AddScoped<ISetLockoutHandler, SetLockoutHandler>();

        // Register client cookie configuration service
        services.AddScoped<IClientCookieConfigurationService, ClientCookieConfigurationService>();

        // Register user realm validation service
        services.AddScoped<IUserRealmValidationService, UserRealmValidationService>();

        return services;
    }

    public static IServiceCollection AddMrWhoDatabase(this WebApplicationBuilder builder)
    {
        // Configure Entity Framework with SQL Server (via Aspire)
        builder.AddSqlServerDbContext<ApplicationDbContext>("mrwhodb", null, optionsBuilder =>
        {
            optionsBuilder.UseOpenIddict();
        });

        return builder.Services;
    }

    /// <summary>
    /// Configures the database for test scenarios with in-memory database
    /// This method is specifically for test projects
    /// </summary>
    public static IServiceCollection AddMrWhoTestDatabase(this IServiceCollection services)
    {
        // Use in-memory database for tests
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseInMemoryDatabase("TestDatabase");
            options.UseOpenIddict();
        });

        return services;
    }

    /// <summary>
    /// Forces database to use EnsureCreatedAsync instead of migrations
    /// Useful for test scenarios where you want predictable database state
    /// </summary>
    public static IServiceCollection ConfigureTestDatabaseBehavior(this IServiceCollection services)
    {
        // Register a configuration that indicates test database behavior
        services.Configure<DatabaseInitializationOptions>(options =>
        {
            options.ForceUseEnsureCreated = true;
            options.SkipMigrations = true;
        });

        return services;
    }

    public static IServiceCollection AddMrWhoIdentity(this IServiceCollection services)
    {
        // Configure Identity
        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // Configure Identity options
        services.Configure<IdentityOptions>(options =>
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

        return services;
    }

    /// <summary>
    /// Configures Identity with client-specific cookie support
    /// </summary>
    public static IServiceCollection AddMrWhoIdentityWithClientCookies(this IServiceCollection services)
    {
        // Configure Identity
        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // Configure Identity options
        services.Configure<IdentityOptions>(options =>
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

        // Add support for multiple cookie configurations
        services.AddScoped<IClientCookieConfigurationService, ClientCookieConfigurationService>();

        return services;
    }

    /// <summary>
    /// Adds cookie configuration for a specific OIDC client
    /// </summary>
    public static IServiceCollection AddClientSpecificCookie(this IServiceCollection services, 
        string clientId, 
        string? cookieName = null,
        Action<CookieAuthenticationOptions>? configureOptions = null)
    {
        var actualCookieName = cookieName ?? $".AspNetCore.Identity.{clientId}";
        var schemeName = $"Identity.Application.{clientId}";

        services.AddAuthentication()
            .AddCookie(schemeName, options =>
            {
                options.Cookie.Name = actualCookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromHours(24);
                options.SlidingExpiration = true;
                
                // Custom configuration
                configureOptions?.Invoke(options);
            });

        return services;
    }

    /// <summary>
    /// Configures multiple client-specific cookies for known clients
    /// </summary>
    public static IServiceCollection AddMrWhoClientCookies(this IServiceCollection services)
    {
        // Admin client cookie
        services.AddClientSpecificCookie("mrwho_admin_web", ".MrWho.Admin", options =>
        {
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.AccessDeniedPath = "/access-denied";
            options.Cookie.Domain = null; // Same domain only
            options.ExpireTimeSpan = TimeSpan.FromHours(8); // Work day session
        });

        // Demo1 client cookie
        services.AddClientSpecificCookie("mrwho_demo1", ".MrWho.Demo1", options =>
        {
            options.LoginPath = "/Account/Login";
            options.LogoutPath = "/Account/Logout";
            options.AccessDeniedPath = "/Account/AccessDenied";
            options.ExpireTimeSpan = TimeSpan.FromHours(2); // Demo session
        });

        // Postman/API client cookie
        services.AddClientSpecificCookie("postman_client", ".MrWho.API", options =>
        {
            options.ExpireTimeSpan = TimeSpan.FromHours(1); // Shorter for API testing
            options.SlidingExpiration = false; // Fixed expiration for API
        });

        return services;
    }

    public static IServiceCollection AddMrWhoOpenIddict(this IServiceCollection services)
    {
        // Configure OpenIddict
        services.AddOpenIddict()
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
                       .SetConfigurationEndpointUris("/.well-known/openid-configuration")
                       .SetUserInfoEndpointUris("/connect/userinfo")

                       // Enable grant types
                       .AllowAuthorizationCodeFlow()
                       .AllowClientCredentialsFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Configure token lifetimes for better refresh token experience
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60))    // 1 hour access tokens
                       .SetRefreshTokenLifetime(TimeSpan.FromDays(14));     // 14 days refresh tokens

                // Configure refresh token behavior
                options.DisableRollingRefreshTokens(); // Disable refresh token rotation for development

                // Register scopes (including API scopes)
                options.RegisterScopes(StandardScopes.OpenId,
                                      OpenIddictConstants.Scopes.Email,
                                      OpenIddictConstants.Scopes.Profile,
                                      OpenIddictConstants.Scopes.Roles,
                                      OpenIddictConstants.Scopes.OfflineAccess, // CRITICAL: Required for refresh tokens
                                      StandardScopes.ApiRead,   // Use constant
                                      StandardScopes.ApiWrite,  // Use constant
                                      StandardScopes.MrWhoUse); // Add mrwho.use scope

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

        return services;
    }

    public static IServiceCollection AddMrWhoAuthorization(this IServiceCollection services)
    {
        // Configure authorization to work with OpenIddict
        services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes("Identity.Application", OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                .Build();
        });

        return services;
    }

    /// <summary>
    /// Configures authorization with support for client-specific authentication schemes
    /// </summary>
    public static IServiceCollection AddMrWhoAuthorizationWithClientCookies(this IServiceCollection services)
    {
        // Configure authorization to work with OpenIddict and client-specific cookies
        services.AddAuthorization(options =>
        {
            // Default policy includes standard Identity.Application and OpenIddict validation
            var schemes = new List<string>
            {
                "Identity.Application",
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                // Add client-specific schemes
                "Identity.Application.mrwho_admin_web",
                "Identity.Application.mrwho_demo1",
                "Identity.Application.postman_client"
            };

            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(schemes.ToArray())
                .Build();

            // Add specific policies for different client types
            options.AddPolicy("AdminOnly", policy =>
                policy.RequireAuthenticatedUser()
                      .AddAuthenticationSchemes("Identity.Application.mrwho_admin_web"));

            options.AddPolicy("DemoAccess", policy =>
                policy.RequireAuthenticatedUser()
                      .AddAuthenticationSchemes("Identity.Application.mrwho_demo1"));

            options.AddPolicy("ApiAccess", policy =>
                policy.RequireAuthenticatedUser()
                      .AddAuthenticationSchemes("Identity.Application.postman_client", 
                                              OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme));
        });

        return services;
    }

    public static IServiceCollection AddMrWhoAntiforgery(this IServiceCollection services)
    {
        // Add antiforgery services
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.SuppressXFrameOptionsHeader = false;
        });

        return services;
    }
}

/// <summary>
/// Configuration options for database initialization behavior
/// </summary>
public class DatabaseInitializationOptions
{
    /// <summary>
    /// When true, forces the use of EnsureCreatedAsync regardless of environment
    /// </summary>
    public bool ForceUseEnsureCreated { get; set; } = false;

    /// <summary>
    /// When true, skips migration checks and application
    /// </summary>
    public bool SkipMigrations { get; set; } = false;

    /// <summary>
    /// When true, recreates the database on each initialization (useful for integration tests)
    /// </summary>
    public bool RecreateDatabase { get; set; } = false;
}