using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Handlers;
using MrWho.Handlers.Auth;
using MrWho.Handlers.Users;
using MrWho.Options;
using MrWho.Services;
using MrWho.Services.Background;
using MrWho.Services.Mediator;
using MrWho.Shared;
using MrWho.Shared.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Client.SystemNetHttp;

namespace MrWho.Extensions;

public static partial class ServiceCollectionExtensions
{
    private static string GetRemoteIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    public static IServiceCollection AddMrWhoServices(this IServiceCollection services)
    {
        // Register shared accessors
        services.AddHttpContextAccessor();
        // Advanced options
        services.AddOptions<OidcAdvancedOptions>().BindConfiguration("OidcAdvanced");
        // JAR/JARM support services
        services.AddMemoryCache();
        services.AddSingleton<IJarReplayCache, InMemoryJarReplayCache>();
        services.AddOptions<JarOptions>().BindConfiguration(JarOptions.SectionName);
        services.AddScoped<IJarRequestValidator, JarRequestValidator>();
        services.AddScoped<IJarValidationService, JarRequestValidator>(); // unified validator

        // Protocol metrics (PJ17 JAR replay metrics + JARM outcomes)
        services.AddSingleton<IProtocolMetrics, InMemoryProtocolMetrics>();

        // Register database access layer
        services.AddScoped<ISeedingService, SeedingService>();
        services.AddScoped<IScopeSeederService, ScopeSeederService>
        ();
        services.AddScoped<IApiResourceSeederService, ApiResourceSeederService>();
        services.AddScoped<IIdentityResourceSeederService, IdentityResourceSeederService>();
        services.AddScoped<IClaimTypeSeederService, ClaimTypeSeederService>();

        // Register client services
        services.AddScoped<IOidcClientService, OidcClientService>();
        services.AddScoped<IOpenIddictScopeSyncService, OpenIddictScopeSyncService>();

        // Client secret hashing and rotation services
        services.AddSingleton<IClientSecretHasher, Pbkdf2ClientSecretHasher>();
        services.AddScoped<IClientSecretService, ClientSecretService>();
        services.AddHostedService<ClientSecretBackfillHostedService>(); // backfill legacy plaintext

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
        services.AddScoped<IOidcAuthorizationHandler, OidcAuthorizationHandler>
        ();
        services.AddScoped<ITokenHandler, TokenHandler>();

        // Register back-channel logout service
        services.AddScoped<IBackChannelLogoutService, BackChannelLogoutService>();
        services.AddHttpClient(); // Required for back-channel logout HTTP calls
        services.AddSingleton<IBackChannelLogoutRetryScheduler, BackChannelLogoutRetryScheduler>();
        services.AddHostedService(sp => (BackChannelLogoutRetryScheduler)sp.GetRequiredService<IBackChannelLogoutRetryScheduler>());
        // ============================================================================
        // DEVICE MANAGEMENT SERVICES
        // ============================================================================

        // Register device management service
        services.AddScoped<IDeviceManagementService, DeviceManagementService>();
        services.AddScoped<IDeviceAutoLoginService, DeviceAutoLoginService>(); // new

        // Register enhanced QR login service (supports both session-based and persistent QR)
        services.AddScoped<IEnhancedQrLoginService, EnhancedQrLoginService>();

        // Keep the original QR login store for backwards compatibility
        services.AddSingleton<IQrLoginStore, InMemoryQrLoginStore>();

        // Register QR code service (if not already registered)
        services.AddSingleton<IQrCodeService, QrCodeService>();

        // Token statistics snapshot service
        services.AddScoped<ITokenStatisticsSnapshotService, TokenStatisticsSnapshotService>();
        services.AddHostedService<TokenStatisticsSnapshotHostedService>();

        // Client role service
        services.AddMemoryCache();
        services.AddScoped<IClientRoleService, ClientRoleService>();

        services.AddHostedService<UserProfileBackfillHostedService>();
        services.AddScoped<IReturnUrlStore, ReturnUrlStore>();
        services.AddHostedService<ReturnUrlCleanupHostedService>();

        // ============================================================================
        // KEY MANAGEMENT & ROTATION
        // ============================================================================
        services.AddOptions<KeyManagementOptions>().BindConfiguration(KeyManagementOptions.SectionName).ValidateDataAnnotations();
        services.AddSingleton<IKeyManagementService, KeyManagementService>();
        services.AddHostedService<KeyRotationHostedService>();
        services.AddSingleton<IPostConfigureOptions<OpenIddict.Server.OpenIddictServerOptions>, OpenIddictServerCredentialsConfigurator>();

        // ============================================================================
        // CONSENT SERVICE
        // ============================================================================
        services.AddScoped<IConsentService, ConsentService>();

        // register security audit writer
        services.AddScoped<ISecurityAuditWriter, SecurityAuditWriter>();
        services.AddScoped<IAuditQueryService, AuditQueryService>();
        services.AddScoped<IAuditIntegrityWriter, AuditIntegrityWriter>();
        services.AddScoped<IAuditIntegrityVerificationService, AuditIntegrityVerificationService>();
        services.AddScoped<IIntegrityHashService, IntegrityHashService>();
        services.AddHttpContextAccessor();
        services.AddSingleton<ICorrelationContextAccessor, CorrelationContextAccessor>();

        services.AddOptions<AuditRetentionOptions>().BindConfiguration(AuditRetentionOptions.SectionName).ValidateDataAnnotations();

        // PAR cleanup background service
        services.AddHostedService<ParCleanupHostedService>();
        services.AddHostedService<AuditChainVerifierHostedService>();
        services.AddHostedService<AuditRetentionHostedService>();

        services.AddOptions<SymmetricSecretPolicyOptions>().BindConfiguration(SymmetricSecretPolicyOptions.SectionName);
        services.AddScoped<ISymmetricSecretPolicy, SymmetricSecretPolicy>();

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

        // Removed AddDbContextFactory due to lifetime conflict; use IServiceScopeFactory for parallel read contexts.

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
            options.Cookie.SameSite = SameSiteMode.None; // cross-site OIDC flows
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Enforce HTTPS (Option 3)
            options.Cookie.Name = CookieSchemeNaming.DefaultCookieName; // Ensure cookie name is explicitly set
            options.Cookie.HttpOnly = true; // Security best practice
            options.ExpireTimeSpan = TimeSpan.FromHours(8); // Consistent with client cookies

            // Add error handling for authentication events
            options.Events = new CookieAuthenticationEvents
            {
                OnRedirectToLogin = context =>
                {
                    // IMPORTANT: Explicitly perform redirect (previous implementation only logged, causing 401 responses)
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<CookieAuthenticationEvents>>();
                    logger.LogDebug("Redirecting unauthenticated request from {Path} to login {LoginPath} (RedirectUri={RedirectUri})", context.Request.Path, options.LoginPath, context.RedirectUri);
                    context.Response.Redirect(context.RedirectUri); // restore default redirect behavior
                    return Task.CompletedTask;
                },
                OnValidatePrincipal = context =>
                {
                    if (context.Principal?.Identity?.IsAuthenticated != true)
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<CookieAuthenticationEvents>>();
                        logger.LogDebug("Principal validation failed for scheme {Scheme}", context.Scheme.Name);
                    }
                    return Task.CompletedTask;
                }
            };
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
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Enforce HTTPS (Option 3)
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

        if (mode == CookieSeparationMode.None)
        {
            return services; // default Identity cookie already configured in AddMrWhoIdentityWithClientCookies
        }

        // Compute the bootstrap cookie name for the admin client without resolving services
        string adminCookieName = mode switch
        {
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

        return services;
    }

    public static IServiceCollection AddMrWhoOpenIddict(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                var issuer = configuration["OpenIddict:Issuer"]; if (!string.IsNullOrWhiteSpace(issuer))
                {
                    options.SetIssuer(new Uri(issuer, UriKind.Absolute));
                }

                options.AddEventHandler(CustomUserInfoHandler.Descriptor);
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       //.SetPushedAuthorizationEndpointUris("/connect/par") // handled by custom ParController
                       .SetTokenEndpointUris("/connect/token")
                       .SetEndSessionEndpointUris("/connect/logout")
                       .SetUserInfoEndpointUris("/connect/userinfo")
                       .SetRevocationEndpointUris("/connect/revocation")
                       .SetIntrospectionEndpointUris("/connect/introspect");
                // Enable flows
                options.AllowAuthorizationCodeFlow().AllowClientCredentialsFlow().AllowRefreshTokenFlow();
                // removed unsupported AllowRequestParameter/AllowRequestUriParameter (custom handlers manage JAR/PAR extraction)
                var enablePassword = string.Equals(Environment.GetEnvironmentVariable("MRWHO_TESTS"), "1", StringComparison.OrdinalIgnoreCase) || environment.IsEnvironment("Testing");
                if (enablePassword)
                {
                    options.AllowPasswordFlow();
                }

                options.RequireProofKeyForCodeExchange();
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60)).SetRefreshTokenLifetime(TimeSpan.FromDays(14));
                if (environment.IsDevelopment())
                {
                    options.DisableRollingRefreshTokens();
                }

                options.RegisterScopes(StandardScopes.OpenId, OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile, OpenIddictConstants.Scopes.Roles, OpenIddictConstants.Scopes.OfflineAccess, StandardScopes.ApiRead, StandardScopes.ApiWrite, StandardScopes.MrWhoUse, "roles.global", "roles.client", "roles.all");
                options.UseAspNetCore().EnableAuthorizationEndpointPassthrough().EnableTokenEndpointPassthrough().EnableEndSessionEndpointPassthrough();
                // JAR/JARM handlers remain
                options.AddEventHandler(JarJarmServerEventHandlers.ConfigurationHandlerDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.ParRequestUriResolutionDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.JarEarlyExtractAndValidateDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.ExtractNormalizeJarmResponseModeDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.NormalizeJarmResponseModeDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.JarValidateRequestObjectDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.RequestConflictAndLimitValidationDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.RedirectUriFallbackDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.ApplyAuthorizationResponseDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.ParModeEnforcementDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.ParConsumptionDescriptor);
                options.AddEventHandler(JarJarmServerEventHandlers.JarModeEnforcementDescriptor); // PJ37 JAR required enforcement
            })
            .AddValidation(options => { options.UseLocalServer(); options.UseAspNetCore(); });
        return services;
    }

    /// <summary>
    /// Adds and configures the OpenIddict client (upstream external providers) using a consistent extension pattern.
    /// Mirrors the inline configuration previously in Program.cs.
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configuration">App configuration (for future use)</param>
    /// <param name="environment">Hosting environment for dev/prod cert decisions</param>
    public static IServiceCollection AddMrWhoOpenIddictClient(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow();
                options.SetRedirectionEndpointUris("/connect/external/callback");
                options.SetPostLogoutRedirectionEndpointUris("/connect/external/signout-callback");

                if (environment.IsDevelopment())
                {
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();
                }
                else
                {
                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey();
                }

                options.UseSystemNetHttp();
                options.UseAspNetCore()
                       .EnableRedirectionEndpointPassthrough()
                       .EnablePostLogoutRedirectionEndpointPassthrough();
                options.UseWebProviders();
            });

        // Upstream client option configurators (already used in Program.cs) stay consistent here so caller just registers them once.
        services.AddSingleton<IConfigureOptions<OpenIddictClientOptions>, ExternalIdpClientOptionsConfigurator>();
        services.AddSingleton<IPostConfigureOptions<OpenIddictClientOptions>, OpenIddictClientOptionsPostConfigurator>();

        return services;
    }

    /// <summary>
    /// Adds standardized rate limiting policies for login, register, token, authorize, userinfo endpoints.
    /// Reads values from configuration section "RateLimiting" with sensible defaults.
    /// </summary>
    public static IServiceCollection AddMrWhoRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("RateLimiting");
        int loginPerHour = section.GetValue<int?>("LoginPerHour") ?? 20;
        int registerPerHour = section.GetValue<int?>("RegisterPerHour") ?? 5;
        int tokenPerHour = section.GetValue<int?>("TokenPerHour") ?? 60;
        int authorizePerHour = section.GetValue<int?>("AuthorizePerHour") ?? 120;
        int userInfoPerHour = section.GetValue<int?>("UserInfoPerHour") ?? 240;
        int devicePerHour = section.GetValue<int?>("DevicePerHour") ?? 60; // new
        int verifyPerHour = section.GetValue<int?>("VerifyPerHour") ?? 120; // new

        services.AddRateLimiter(options =>
        {
            options.OnRejected = (context, token) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return ValueTask.CompletedTask;
            };
            options.AddPolicy("rl.login", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, loginPerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
            options.AddPolicy("rl.register", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, registerPerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
            options.AddPolicy("rl.token", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, tokenPerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
            options.AddPolicy("rl.authorize", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, authorizePerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
            options.AddPolicy("rl.userinfo", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, userInfoPerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
            options.AddPolicy("rl.device", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, devicePerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
            options.AddPolicy("rl.verify", ctx => RateLimitPartition.GetFixedWindowLimiter(GetRemoteIp(ctx), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, verifyPerHour),
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            }));
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

        return services;
    }

    public static IServiceCollection AddMrWhoAntiforgery(this IServiceCollection services)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-XSRF-TOKEN";
        });
        return services;
    }
}
