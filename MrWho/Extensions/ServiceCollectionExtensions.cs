using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.Cookies; // ensure CookieAuthenticationOptions is available
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics; // added for RelationalEventId
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Handlers.Users; // added for user handler interfaces/implementations
using MrWho.Services;
using OpenIddict.Abstractions;
using MrWho.Shared;
using MrWho.Options; // for CookieSeparationMode
using MrWho.Shared.Authentication; // for CookieSchemeNaming

namespace MrWho.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoServices(this IServiceCollection services)
    {
        // Register shared accessors
        services.AddHttpContextAccessor();

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
        
        // Register dynamic client configuration service
        services.AddScoped<IDynamicClientConfigurationService, DynamicClientConfigurationService>();

        // CORRECTED: Add complete dynamic client cookie registration system
        services.AddHostedService<DynamicClientCookieService>();
        services.AddSingleton<IDynamicClientCookieRegistrar, DynamicClientCookieRegistrar>();

        // Add infrastructure for dynamic cookie options
        services.AddSingleton<IConfigureNamedOptions<CookieAuthenticationOptions>, DynamicCookieOptionsConfigurator>();

        // CORRECTED: Add dynamic authorization policy provider that loads schemes from database
        // ? SINGLE SOURCE OF TRUTH: All authorization policies (static + dynamic) centralized here
        services.AddSingleton<IAuthorizationPolicyProvider, DynamicAuthorizationPolicyProvider>();

        // Register realm validation service
        services.AddScoped<IUserRealmValidationService, UserRealmValidationService>();

        // Register user handlers
        services.AddScoped<IGetUsersHandler, GetUsersHandler>();
        services.AddScoped<IGetUserHandler, GetUserHandler>();
        services.AddScoped<ICreateUserHandler, CreateUserHandler>();
        services.AddScoped<IUpdateUserHandler, UpdateUserHandler>();
        services.AddScoped<IDeleteUserHandler, DeleteUserHandler>();

        // Register authorization, token and userinfo handlers
        services.AddScoped<IOidcAuthorizationHandler, OidcAuthorizationHandler>();
        services.AddScoped<ITokenHandler, TokenHandler>();
        services.AddScoped<IUserInfoHandler, MrWho.Handlers.UserInfoHandler>(); // disambiguate

        // Register back-channel logout service
        services.AddScoped<IBackChannelLogoutService, BackChannelLogoutService>();
        services.AddHttpClient(); // Required for back-channel logout HTTP calls

        // ============================================================================
        // DEVICE MANAGEMENT SERVICES
        // ============================================================================

        // Register device management service
        services.AddScoped<IDeviceManagementService, DeviceManagementService>();

        // Register enhanced QR login service (supports both session-based and persistent QR)
        services.AddScoped<IEnhancedQrLoginService, EnhancedQrLoginService>();

        // Keep the original QR login store for backwards compatibility
        services.AddSingleton<IQrLoginStore, InMemoryQrLoginStore>();

        // Register QR code service (if not already registered)
        services.AddSingleton<IQrCodeService, QrCodeService>();

        // Token statistics snapshot service
        services.AddScoped<ITokenStatisticsSnapshotService, TokenStatisticsSnapshotService>();
        services.AddHostedService<TokenStatisticsSnapshotHostedService>();

        return services;
    }

    public static IServiceCollection AddMrWhoDatabase(this WebApplicationBuilder builder)
    {
        // PostgreSQL-only database configuration; migrations live in this assembly
        var config = builder.Configuration;
        var services = builder.Services;
        var isDevelopment = builder.Environment.IsDevelopment();

        var connectionName = config["Database:ConnectionName"] ?? "mrwhodb";
        var connectionString = config.GetConnectionString(connectionName) ?? config[$"ConnectionStrings:{connectionName}"];

        // Provide a sensible local default for tooling/migrations if not configured
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            connectionString = "Host=localhost;Database=MrWho;Username=postgres;Password=ChangeMe123!";
        }

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseNpgsql(connectionString);

            if (isDevelopment)
			{
                options.ConfigureWarnings(w => w.Log(RelationalEventId.PendingModelChangesWarning));
                options.EnableDetailedErrors();
                options.EnableSensitiveDataLogging();
            }

            // Required by OpenIddict EF stores
            options.UseOpenIddict();
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

        // Ensure default Identity cookie uses our connect/* routes and SameSite=None for cross-site flows
        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/connect/login";
            options.LogoutPath = "/connect/logout";
            options.AccessDeniedPath = "/connect/access-denied";
            options.SlidingExpiration = true;
            options.Cookie.SameSite = SameSiteMode.None; // Required for external IdP (cross-site) login/logout
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
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
        var schemeName = CookieSchemeNaming.BuildClientScheme(clientId);
        var actualCookieName = cookieName ?? CookieSchemeNaming.BuildClientCookie(clientId);

        services.AddAuthentication()
            .AddCookie(schemeName, options =>
            {
                options.Cookie.Name = actualCookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.None; // Required for cross-site OIDC redirects
                options.ExpireTimeSpan = TimeSpan.FromHours(24);
                options.SlidingExpiration = true;
                
                // Custom configuration
                configureOptions?.Invoke(options);
            });

        return services;
    }

    /// <summary>
    /// Configures client-specific cookies for essential clients (fallback + database clients via DynamicClientCookieService)
    /// Only the admin client is statically registered to guarantee bootstrap login; all others are database-driven.
    /// </summary>
    public static IServiceCollection AddMrWhoClientCookies(this IServiceCollection services, IConfiguration? configuration = null)
    {
        // Determine cookie separation mode from configuration (fallback to ByClient)
        var modeString = configuration?["MrWho:CookieSeparationMode"] ?? "ByClient";
        var mode = Enum.TryParse<CookieSeparationMode>(modeString, ignoreCase: true, out var parsed)
            ? parsed
            : CookieSeparationMode.ByClient;

        // Compute the bootstrap cookie name for the admin client without resolving services
        string adminCookieName = mode switch
        {
            CookieSeparationMode.None => CookieSchemeNaming.DefaultCookieName,
            CookieSeparationMode.ByRealm => CookieSchemeNaming.BuildRealmCookie("admin"), // admin client lives in the 'admin' realm
            _ => CookieSchemeNaming.BuildClientCookie("mrwho_admin_web") // ByClient (default)
        };

        services.AddClientSpecificCookie("mrwho_admin_web", adminCookieName, options =>
        {
            options.LoginPath = "/connect/login";
            options.LogoutPath = "/connect/logout";
            options.AccessDeniedPath = "/connect/access-denied";
            options.Cookie.Domain = null; // Same domain only; domain overrides applied globally in Program.cs
            options.ExpireTimeSpan = TimeSpan.FromHours(8); // Work day session
        });

        // Note: Remaining clients are registered dynamically by DynamicClientCookieService from the database.
        return services;
    }

    public static IServiceCollection AddMrWhoOpenIddict(this IServiceCollection services, IConfiguration configuration)
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
                // Allow setting a static issuer via configuration/environment for reverse proxy/Docker scenarios
                var issuer = configuration["OpenIddict:Issuer"]; // maps from env OPENIDDICT__ISSUER
                if (!string.IsNullOrWhiteSpace(issuer))
                {
                    options.SetIssuer(new Uri(issuer, UriKind.Absolute));
                }

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

                // For demo/API compatibility: issue plain signed (non-encrypted) access tokens so JwtBearer can validate
                // (Current tokens are JWE with RSA-OAEP + A256CBC-HS512 making them unparsable by standard decoders against Authority keys.)
                options.DisableAccessTokenEncryption();

                // Register the ASP.NET Core host and enable passthrough for the authorization endpoint
                options.UseAspNetCore()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableTokenEndpointPassthrough() // ADDED: allow custom minimal API handler for /connect/token
                       .EnableEndSessionEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }

    /// <summary>
    /// Configures authorization with dynamic client-specific authentication schemes loaded from database
    /// ALL policies are now handled by DynamicAuthorizationPolicyProvider for centralized configuration
    /// </summary>
    public static IServiceCollection AddMrWhoAuthorizationWithClientCookies(this IServiceCollection services)
    {
        // Configure authorization - all policies handled by DynamicAuthorizationPolicyProvider
        services.AddAuthorization();

        // The DynamicAuthorizationPolicyProvider (registered in AddMrWhoServices) handles:
        // ? UserInfoPolicy - Static security policy for OpenIddict validation
        // ? AdminOnly - Static policy for admin client authentication  
        // ? DemoAccess - Static policy for demo client authentication
        // ? ApiAccess - Static policy for API client + OpenIddict validation
        // ? Default Policy - Dynamic policy loading ALL client schemes from database
        // ? Client_{clientId} - Dynamic policies for any client (e.g., "Client_my_custom_client")
        //
        // Benefits:
        // ?? Single source of truth for all authorization configuration
        // ?? Database-driven default policy with automatic client inclusion
        // ?? No code changes needed when adding new clients to database
        // ?? Centralized policy logic with proper fallback handling

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