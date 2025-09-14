using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MrWhoAdmin.Web.Extensions;
using MrWhoAdmin.Web.Services;
using Radzen;

namespace MrWhoAdmin.Web.Extensions;

public sealed record AdminProfile
{
    public string Name { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string Authority { get; init; } = string.Empty;
    public string ApiBaseUrl { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public bool AllowSelfSigned { get; init; }
}

public interface IAdminProfileService
{
    IReadOnlyList<AdminProfile> GetProfiles();
    AdminProfile? GetCurrentProfile(HttpContext? context = null);
    AdminProfile? Find(string name);
    void SetCurrentProfile(HttpContext context, string name);
    string GetProfileCookieName();
    string GetCookieScheme(AdminProfile profile);
    string GetOidcScheme(AdminProfile profile);
}

internal sealed class AdminProfileService : IAdminProfileService
{
    private readonly List<AdminProfile> _profiles;
    private readonly IHttpContextAccessor _http;
    private const string ProfileCookie = ".MrWho.Admin.CurrentProfile";

    public AdminProfileService(IConfiguration config, IHttpContextAccessor http)
    {
        _http = http;
        _profiles = config.GetSection("AdminProfiles").Get<List<AdminProfile>>() ?? new List<AdminProfile>();
    }

    public IReadOnlyList<AdminProfile> GetProfiles() => _profiles;
    public string GetProfileCookieName() => ProfileCookie;

    public AdminProfile? GetCurrentProfile(HttpContext? context = null)
    {
        context ??= _http.HttpContext;
        if (context == null)
        {
            return _profiles.FirstOrDefault();
        }

        if (context.Items.TryGetValue(typeof(AdminProfile), out var obj) && obj is AdminProfile cached)
        {
            return cached;
        }

        if (context.Request.Cookies.TryGetValue(ProfileCookie, out var name))
        {
            var prof = _profiles.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
            if (prof != null)
            {
                context.Items[typeof(AdminProfile)] = prof;
            }

            return prof ?? _profiles.FirstOrDefault();
        }
        return _profiles.FirstOrDefault();
    }

    public AdminProfile? Find(string name) => _profiles.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));

    public void SetCurrentProfile(HttpContext context, string name)
    {
        var profile = Find(name);
        if (profile == null)
        {
            return;
        }

        if (!context.Response.HasStarted)
        {
            try
            {
                context.Response.Cookies.Append(ProfileCookie, profile.Name, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Lax,
                    Secure = context.Request.IsHttps,
                    Expires = DateTimeOffset.UtcNow.AddDays(7)
                });
            }
            catch { }
        }
        context.Items[typeof(AdminProfile)] = profile;
    }

    public string GetCookieScheme(AdminProfile profile) => $"AdminCookies:{profile.Name}";
    public string GetOidcScheme(AdminProfile profile) => $"OIDC:{profile.Name}";
}

internal sealed class ProfileApiBaseHandler : DelegatingHandler
{
    private readonly IAdminProfileService _profiles;
    private readonly IHttpContextAccessor _http;
    private readonly ILogger<ProfileApiBaseHandler> _logger;
    public ProfileApiBaseHandler(IAdminProfileService profiles, IHttpContextAccessor http, ILogger<ProfileApiBaseHandler> logger)
    { _profiles = profiles; _http = http; _logger = logger; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            var ctx = _http.HttpContext;
            var profile = _profiles.GetCurrentProfile(ctx);
            if (profile != null && Uri.TryCreate(profile.ApiBaseUrl, UriKind.Absolute, out var baseUri))
            {
                if (request.RequestUri != null && !request.RequestUri.IsAbsoluteUri)
                {
                    request.RequestUri = new Uri(baseUri, request.RequestUri);
                }
                else if (request.RequestUri != null && request.RequestUri.IsAbsoluteUri && !string.Equals(request.RequestUri.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase))
                {
                    var rebased = new Uri(baseUri, request.RequestUri.PathAndQuery);
                    request.RequestUri = rebased;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ProfileApiBaseHandler could not adjust base URI");
        }
        return base.SendAsync(request, cancellationToken);
    }
}

/// <summary>
/// Extension methods for configuring services in the DI container
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Radzen UI component services
    /// </summary>
    public static IServiceCollection AddRadzenServices(this IServiceCollection services)
    {
        services.AddRadzenComponents();
        services.AddScoped<DialogService>();
        services.AddScoped<NotificationService>();
        services.AddScoped<TooltipService>();
        services.AddScoped<ContextMenuService>();

        return services;
    }

    /// <summary>
    /// Adds HTTP related services
    /// </summary>
    public static IServiceCollection AddHttpServices(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddTransient<AuthenticationDelegatingHandler>();
        services.AddTransient<ProfileApiBaseHandler>();

        // Add token refresh service
        services.AddScoped<ITokenRefreshService, TokenRefreshService>();

        // Add Blazor authentication service
        services.AddScoped<IBlazorAuthService, BlazorAuthService>();

        // Add authentication failure service
        services.AddScoped<IAuthenticationFailureService, AuthenticationFailureService>();

        // Add circuit handler service for better Blazor Server error handling
        services.AddScoped<CircuitHandlerService>();

        // CRITICAL: Ensure antiforgery services are explicitly added
        // This should be automatic with Blazor Server, but we'll add it explicitly to fix the error
        services.AddAntiforgery();

        // Add direct health service for local health checks
        services.AddScoped<IDirectHealthService, DirectHealthService>();

        // Register HealthController for direct service calls
        services.AddScoped<MrWhoAdmin.Web.Controllers.HealthController>();

        // Configure HttpClient defaults for better connection management
        services.ConfigureHttpClientDefaults(builder =>
        {
            builder.ConfigureHttpClient(client =>
            {
                client.Timeout = TimeSpan.FromSeconds(30); // Default timeout
            });

            // Configure connection lifetime to prevent stale connections
            builder.ConfigurePrimaryHttpMessageHandler(() =>
            {
                return new SocketsHttpHandler()
                {
                    PooledConnectionLifetime = TimeSpan.FromMinutes(15), // Refresh connections every 15 minutes
                    PooledConnectionIdleTimeout = TimeSpan.FromMinutes(5), // Close idle connections after 5 minutes
                    MaxConnectionsPerServer = 10 // Limit concurrent connections per server
                };
            });
        });

        return services;
    }

    /// <summary>
    /// Adds API client services with authentication
    /// </summary>
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        var mrWhoApiBaseUrl = configuration.GetValue<string>("MrWhoApi:BaseUrl") ?? "https://localhost:7113/";
        var defaultTimeout = TimeSpan.FromSeconds(30);

        void ConfigureClient(HttpClient client)
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        }

        IServiceCollection Add<TInterface, TImpl>() where TInterface : class where TImpl : class, TInterface
        {
            services.AddHttpClient<TInterface, TImpl>(ConfigureClient)
                .AddHttpMessageHandler<AuthenticationDelegatingHandler>()
                .AddHttpMessageHandler<ProfileApiBaseHandler>();
            return services;
        }

        Add<IRealmsApiService, RealmsApiService>();
        Add<IClientsApiService, ClientsApiService>();
        Add<IClientTypesApiService, ClientTypesApiService>();
        Add<IUsersApiService, UsersApiService>();
        Add<IRolesApiService, RolesApiService>();
        Add<IScopesApiService, ScopesApiService>();
        Add<IApiResourcesApiService, ApiResourcesApiService>();
        Add<IIdentityResourcesApiService, IdentityResourcesApiService>();
        Add<IClaimTypesApiService, ClaimTypesApiService>();
        Add<ISessionsApiService, SessionsApiService>();
        Add<IClientUsersApiService, ClientUsersApiService>();
        Add<IUserClientsApiService, UserClientsApiService>();
        Add<IRegistrationsApiService, RegistrationsApiService>();
        Add<IAuditLogsApiService, AuditLogsApiService>();
        Add<ITokenStatisticsApiService, TokenStatisticsApiService>();
        Add<IApiUsageApiService, ApiUsageApiService>();
        Add<IIdentityProvidersApiService, IdentityProvidersApiService>();
        Add<IClientRolesApiService, ClientRolesApiService>();
        Add<IClientRoleUsersApiService, ClientRoleUsersApiService>();
        Add<IClientRegistrationsApiService, ClientRegistrationsApiService>();

        // Health API (local) – no auth handlers required
        services.AddHttpClient<IHealthApiService, HealthApiService>(client =>
        {
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        });

        return services;
    }

    /// <summary>
    /// Configures authentication services including OpenID Connect
    /// CORRECTED: Use standard OIDC with server-side session isolation
    /// </summary>
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddMemoryCache();
        services.AddSingleton<IAdminProfileService, AdminProfileService>();

        using var scope = services.BuildServiceProvider();
        var profileService = scope.GetRequiredService<IAdminProfileService>();
        var profiles = profileService.GetProfiles();

        if (profiles.Count <= 1)
        {
            // Fallback to existing single-profile logic using first profile OR appsettings Authentication section
            const string adminCookieScheme = "AdminCookies";

            // Compute admin cookie name using the same convention as the server
            static string GetMrWhoCookieName(string clientId) => $".MrWho.{clientId}";
            var clientId = profiles.FirstOrDefault()?.ClientId ?? (configuration.GetSection("Authentication").GetValue<string>("ClientId") ?? "mrwho_admin_web");
            var adminCookieName = GetMrWhoCookieName(clientId);

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = adminCookieScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme; // Use standard OIDC
            })
            .AddCookie(adminCookieScheme, options =>
            {
                options.Cookie.Name = adminCookieName; // Align with server standard .MrWho.{clientId}
                options.Cookie.Path = "/";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.None; // Required for cross-site OIDC flows
                options.ExpireTimeSpan = TimeSpan.FromHours(8);
                options.SlidingExpiration = true;
                options.LoginPath = "/login";
                options.LogoutPath = "/logout";

                // CRITICAL: Add event to check for session invalidation on each request
                options.Events.OnValidatePrincipal = async context =>
                {
                    var cache = context.HttpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>();
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();

                    if (context.Principal?.Identity?.IsAuthenticated == true)
                    {
                        var subjectClaim = context.Principal.FindFirst("sub")?.Value;

                        if (!string.IsNullOrEmpty(subjectClaim))
                        {
                            // Check if this subject has been logged out via back-channel logout
                            if (cache.TryGetValue($"logout_{subjectClaim}", out var logoutInfo))
                            {
                                logger.LogInformation("Admin Web session invalidated for subject {Subject} due to back-channel logout", subjectClaim);

                                // Reject the principal to force re-authentication
                                context.RejectPrincipal();
                                await context.HttpContext.SignOutAsync(adminCookieScheme);

                                // Remove the logout notification after processing
                                cache.Remove($"logout_{subjectClaim}");
                            }
                        }
                    }
                };
            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => // Use standard scheme
            {
                options.SignInScheme = adminCookieScheme;
                ConfigureOpenIdConnect(options, configuration, profiles.FirstOrDefault());
            });
        }
        else
        {
            // Multi-profile dynamic policy scheme
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "AdminDynamic";
                options.DefaultChallengeScheme = "AdminDynamic";
            })
            .AddPolicyScheme("AdminDynamic", "Dynamic admin scheme", o =>
            {
                o.ForwardDefaultSelector = ctx =>
                {
                    var ps = ctx.RequestServices.GetRequiredService<IAdminProfileService>();
                    var prof = ps.GetCurrentProfile(ctx);
                    return prof != null ? ps.GetCookieScheme(prof) : null;
                };
            });

            foreach (var profile in profiles)
            {
                var cookieScheme = profileService.GetCookieScheme(profile);
                var oidcScheme = profileService.GetOidcScheme(profile);
                services.AddAuthentication().AddCookie(cookieScheme, options =>
                {
                    options.Cookie.Name = $".MrWho.{profile.ClientId}";
                    options.Cookie.SameSite = SameSiteMode.None;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    options.LoginPath = "/login";
                    options.LogoutPath = "/logout";
                });
                services.AddAuthentication().AddOpenIdConnect(oidcScheme, options =>
                {
                    options.SignInScheme = cookieScheme;
                    ConfigureOpenIdConnect(options, configuration, profile);
                });
            }
        }
        return services;
    }

    /// <summary>
    /// Adds authorization services
    /// </summary>
    public static IServiceCollection AddAuthorizationServices(this IServiceCollection services)
    {
        services.AddAuthorization();
        services.AddCascadingAuthenticationState();
        return services;
    }

    /// <summary>
    /// Configures OpenID Connect options
    /// </summary>
    private static void ConfigureOpenIdConnect(OpenIdConnectOptions options, IConfiguration configuration, AdminProfile? profile = null)
    {
        var authConfig = configuration.GetSection("Authentication");
        if (profile != null)
        {
            options.Authority = profile.Authority.TrimEnd('/') + "/";
            options.ClientId = profile.ClientId;
            options.ClientSecret = profile.ClientSecret;
            options.RequireHttpsMetadata = profile.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            if (profile.AllowSelfSigned)
            {
                options.BackchannelHttpHandler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
            }
        }
        else
        {
            options.Authority = authConfig.GetValue<string>("Authority") ?? "https://localhost:7113/";
            options.ClientId = authConfig.GetValue<string>("ClientId") ?? "mrwho_admin_web";
            options.ClientSecret = authConfig.GetValue<string>("ClientSecret") ?? string.Empty;
            var defaultRequireHttps = options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            options.RequireHttpsMetadata = authConfig.GetValue("RequireHttpsMetadata", defaultRequireHttps);
            if (authConfig.GetValue<bool>("AllowSelfSigned", false))
            {
                options.BackchannelHttpHandler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
            }
        }
        options.ResponseType = "code";
        options.SaveTokens = true; // CRITICAL: This saves tokens for API calls
        options.GetClaimsFromUserInfoEndpoint = true;
        options.UsePkce = true; // Enable PKCE for better security
        options.CallbackPath = "/signin-oidc";
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        options.SignedOutRedirectUri = "/signed-out";
        options.RemoteSignOutPath = "/signout-oidc";
        options.MetadataAddress = options.Authority.TrimEnd('/') + "/.well-known/openid-configuration";
        options.RefreshInterval = TimeSpan.FromMinutes(30); // Check for refresh every 30 minutes
        options.UseTokenLifetime = true; // Use the token's actual lifetime
        options.SkipUnrecognizedRequests = true;

        // Development convenience: allow trusting self-signed certificates for the OIDC backchannel
        // Only enable when explicitly configured
        var allowSelfSigned = authConfig.GetValue<bool>("AllowSelfSigned", false);
        HttpClientHandler? backchannelHandler = null;
        if (allowSelfSigned)
        {
            backchannelHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            options.BackchannelHttpHandler = backchannelHandler;
        }

        // If a metadata address is specified, force discovery via a custom ConfigurationManager
        if (!string.IsNullOrWhiteSpace(options.MetadataAddress))
        {
            var retriever = new Microsoft.IdentityModel.Protocols.HttpDocumentRetriever
            {
                RequireHttps = options.RequireHttpsMetadata
            };
            if (backchannelHandler != null)
            {
                // Use a custom HttpClient with our permissive handler for self-signed certs
                retriever = new Microsoft.IdentityModel.Protocols.HttpDocumentRetriever(new HttpClient(backchannelHandler, disposeHandler: false))
                {
                    RequireHttps = options.RequireHttpsMetadata
                };
            }

            options.ConfigurationManager = new Microsoft.IdentityModel.Protocols.ConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>(
                options.MetadataAddress,
                new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfigurationRetriever(),
                retriever);
        }

        ConfigureScopes(options);
        ConfigureClaimActions(options);
        ConfigureEvents(options);
    }

    /// <summary>
    /// Configures OAuth2/OIDC scopes
    /// </summary>
    private static void ConfigureScopes(OpenIdConnectOptions options)
    {
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("roles");
        // Removed offline_access to avoid refresh tokens for Admin Web and avoid step-up prompts by policy
        // options.Scope.Add("offline_access");
        options.Scope.Add("mrwho.use"); // Required for admin policy protected endpoints
    }

    /// <summary>
    /// Configures claim actions for proper claim mapping
    /// </summary>
    private static void ConfigureClaimActions(OpenIdConnectOptions options)
    {
        // Since we're not using UserInfo endpoint due to 403 issue, get claims from ID token
        options.ClaimActions.Clear();

        // Remove technical OpenIddict claims we don't need
        options.ClaimActions.DeleteClaim("iss");
        options.ClaimActions.DeleteClaim("aud");
        options.ClaimActions.DeleteClaim("exp");
        options.ClaimActions.DeleteClaim("iat");
        options.ClaimActions.DeleteClaim("nonce");
        options.ClaimActions.DeleteClaim("at_hash");
        options.ClaimActions.DeleteClaim("azp");
        options.ClaimActions.DeleteClaim("oi_au_id");
        options.ClaimActions.DeleteClaim("oi_tbn_id");

        // Map claims from ID token (since UserInfo is disabled)
        options.ClaimActions.MapJsonKey("sub", "sub");
        options.ClaimActions.MapJsonKey("name", "name");
        options.ClaimActions.MapJsonKey("given_name", "given_name");
        options.ClaimActions.MapJsonKey("family_name", "family_name");
        options.ClaimActions.MapJsonKey("email", "email");
        options.ClaimActions.MapJsonKey("email_verified", "email_verified");
        options.ClaimActions.MapJsonKey("preferred_username", "preferred_username");
        options.ClaimActions.MapJsonKey("phone_number", "phone_number");
        options.ClaimActions.MapJsonKey("phone_number_verified", "phone_number_verified");
        options.ClaimActions.MapJsonKey("role", "role");
    }

    /// <summary>
    /// Configures OpenID Connect events for logging and debugging
    /// </summary>
    private static void ConfigureEvents(OpenIdConnectOptions options)
    {
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Redirecting to identity provider (scheme: {Scheme})", context.Scheme.Name);
                var authority = context.Options.Authority?.TrimEnd('/') ?? string.Empty;
                if (!string.IsNullOrEmpty(authority))
                {
                    var desiredAuthorize = $"{authority}/connect/authorize";
                    if (!string.Equals(context.ProtocolMessage.IssuerAddress, desiredAuthorize, StringComparison.OrdinalIgnoreCase))
                    {
                        context.ProtocolMessage.IssuerAddress = desiredAuthorize;
                    }
                }
                if (context.Properties?.Items.TryGetValue("force", out var force) == true && force == "1")
                {
                    context.ProtocolMessage.Prompt = "login";
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx =>
            {
                var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Token validated for scheme {Scheme}", ctx.Scheme.Name);
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError(ctx.Exception, "Authentication failed for scheme {Scheme}", ctx.Scheme.Name);
                var errorMessage = Uri.EscapeDataString(ctx.Exception?.Message ?? "Unknown error");
                ctx.Response.Redirect($"/auth/error?error={errorMessage}");
                ctx.HandleResponse();
                return Task.CompletedTask;
            }
        };
    }
}
