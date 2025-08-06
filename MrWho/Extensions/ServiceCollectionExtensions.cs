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

namespace MrWho.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoServices(this IServiceCollection services)
    {
        // Register custom services
        services.AddScoped<IOidcClientService, OidcClientService>();
        services.AddScoped<ISeedingService, SeedingService>();
        services.AddScoped<IScopeSeederService, ScopeSeederService>();
        services.AddScoped<IApiResourceSeederService, ApiResourceSeederService>();
        services.AddScoped<IIdentityResourceSeederService, IdentityResourceSeederService>();

        // Register token handler
        services.AddScoped<ITokenHandler, TokenHandler>();

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
                       .SetConfigurationEndpointUris("/.well-known/openid_configuration")
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