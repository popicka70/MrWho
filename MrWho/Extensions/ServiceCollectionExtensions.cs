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
using Microsoft.Extensions.Options;

namespace MrWho.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoServices(this IServiceCollection services)
    {
        // Register database access layer
        services.AddScoped<ISeedingService, SeedingService>();
        services.AddScoped<IScopeSeederService, ScopeSeederService>();
        services.AddScoped<IApiResourceSeederService, ApiResourceSeederService>();
        services.AddScoped<IIdentityResourceSeederService, IdentityResourceSeederService>();

        // Register client services
        services.AddScoped<IOidcClientService, OidcClientService>();
        services.AddScoped<IOpenIddictScopeSyncService, OpenIddictScopeSyncService>();

        // Register client cookie services
        services.AddScoped<IDynamicCookieService, DynamicCookieService>();

        // CORRECTED: Add complete dynamic client cookie registration system
        services.AddHostedService<DynamicClientCookieService>();
        
        // Add infrastructure for dynamic cookie options
        services.AddSingleton<IConfigureNamedOptions<CookieAuthenticationOptions>, DynamicCookieOptionsConfigurator>();

        // Register realm validation service
        services.AddScoped<IUserRealmValidationService, UserRealmValidationService>();

        // Register user handlers
        services.AddScoped<IGetUsersHandler, GetUsersHandler>();
        services.AddScoped<IGetUserHandler, GetUserHandler>();
        services.AddScoped<ICreateUserHandler, CreateUserHandler>();
        services.AddScoped<IUpdateUserHandler, UpdateUserHandler>();
        services.AddScoped<IDeleteUserHandler, DeleteUserHandler>();

        // Register authorization and token handlers
        services.AddScoped<IOidcAuthorizationHandler, OidcAuthorizationHandler>();
        services.AddScoped<IUserInfoHandler, UserInfoHandler>();

        // Register back-channel logout service
        services.AddScoped<IBackChannelLogoutService, BackChannelLogoutService>();
        services.AddHttpClient(); // Required for back-channel logout HTTP calls

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
    /// Configures client-specific cookies for essential clients (fallback + database clients via DynamicClientCookieService)
    /// CORRECTED: This now handles only essential/static clients, database clients are handled by DynamicClientCookieService
    /// </summary>
    public static IServiceCollection AddMrWhoClientCookies(this IServiceCollection services)
    {
        // ESSENTIAL: Admin client cookie (always needed for bootstrap)
        services.AddClientSpecificCookie("mrwho_admin_web", ".MrWho.Admin", options =>
        {
            options.LoginPath = "/connect/login";
            options.LogoutPath = "/connect/logout";
            options.AccessDeniedPath = "/connect/access-denied";
            options.Cookie.Domain = null; // Same domain only
            options.ExpireTimeSpan = TimeSpan.FromHours(8); // Work day session
        });

        // OPTIONAL: Keep Demo1 for development/testing
        services.AddClientSpecificCookie("mrwho_demo1", ".MrWho.Demo1", options =>
        {
            options.LoginPath = "/connect/login";
            options.LogoutPath = "/connect/logout";
            options.AccessDeniedPath = "/connect/access-denied";
            options.Cookie.Domain = null; // Same domain only
            options.ExpireTimeSpan = TimeSpan.FromHours(2); // Demo session timeout
        });

        // OPTIONAL: Keep Postman for API testing
        services.AddClientSpecificCookie("postman_client", ".MrWho.API", options =>
        {
            options.ExpireTimeSpan = TimeSpan.FromHours(1); // Shorter for API testing
            options.SlidingExpiration = false; // Fixed expiration for API
        });

        // ?? DYNAMIC CLIENTS: All other clients are automatically registered by DynamicClientCookieService
        // which loads from database and creates schemes like:
        // - "my_custom_client" ? ".MrWho.MyCustomClient" 
        // - "partner_app" ? ".MrWho.PartnerApp"
        // - etc. (unlimited scalability!)

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

            // CRITICAL: Add specific policy for UserInfo endpoint that only uses OpenIddict validation
            options.AddPolicy("UserInfoPolicy", policy =>
                policy.RequireAuthenticatedUser()
                      .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme));
        });

        return services;
    }

    /// <summary>
    /// Configures authorization with support for client-specific authentication schemes
    /// CORRECTED: Now supports both static and dynamic client schemes
    /// </summary>
    public static IServiceCollection AddMrWhoAuthorizationWithClientCookies(this IServiceCollection services)
    {
        // Configure authorization to work with OpenIddict and client-specific cookies
        services.AddAuthorization(options =>
        {
            // Base schemes that are always available
            var baseSchemes = new List<string>
            {
                "Identity.Application",
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                // Essential client-specific schemes (static registration)
                "Identity.Application.mrwho_admin_web",
                "Identity.Application.mrwho_demo1", 
                "Identity.Application.postman_client"
            };

            // CORRECTED: Dynamic schemes will be added by DynamicClientCookieService
            // The authorization system will automatically discover them at runtime

            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(baseSchemes.ToArray())
                .Build();

            // CRITICAL: Add specific policy for UserInfo endpoint that only uses OpenIddict validation
            options.AddPolicy("UserInfoPolicy", policy =>
                policy.RequireAuthenticatedUser()
                      .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme));

            // Essential client policies (static)
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

            // ?? DYNAMIC CLIENT POLICIES: Can be created at runtime as needed
            // Example: services.AddPolicy($"Client_{clientId}", policy => ...)
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