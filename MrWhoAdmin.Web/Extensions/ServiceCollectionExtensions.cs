using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MrWhoAdmin.Web.Services;
using MrWhoAdmin.Web.Extensions;
using Radzen;
using System.Security.Claims; // Added for claim manipulation
using System.Text.Json; // For JsonElement processing

namespace MrWhoAdmin.Web.Extensions;

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

        // Register MrWho API clients with authentication and improved timeout handling
        services.AddHttpClient<IRealmsApiService, RealmsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IClientsApiService, ClientsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IClientTypesApiService, ClientTypesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IUsersApiService, UsersApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IRolesApiService, RolesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IScopesApiService, ScopesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IApiResourcesApiService, ApiResourcesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IIdentityResourcesApiService, IdentityResourcesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IClaimTypesApiService, ClaimTypesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add Sessions API service
        services.AddHttpClient<ISessionsApiService, SessionsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout; // Set explicit timeout
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add Client Users API service
        services.AddHttpClient<IClientUsersApiService, ClientUsersApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add User Clients API service
        services.AddHttpClient<IUserClientsApiService, UserClientsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add Registrations API service
        services.AddHttpClient<IRegistrationsApiService, RegistrationsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add Audit Logs API service
        services.AddHttpClient<IAuditLogsApiService, AuditLogsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add Token Statistics API service
        services.AddHttpClient<ITokenStatisticsApiService, TokenStatisticsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add API Usage API service
        services.AddHttpClient<IApiUsageApiService, ApiUsageApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Identity Providers API service
        services.AddHttpClient<IIdentityProvidersApiService, IdentityProvidersApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Client Roles API service
        services.AddHttpClient<IClientRolesApiService, ClientRolesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IClientRoleUsersApiService, ClientRoleUsersApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Health API service - local endpoints
        services.AddHttpClient<IHealthApiService, HealthApiService>(client =>
        {
            // Health endpoints are local to this web application
            // We'll set the base address dynamically in the service
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = defaultTimeout;
        });
        // Note: No authentication handler needed for local health endpoints
        
        return services;
    }

    /// <summary>
    /// Configures authentication services including OpenID Connect
    /// CORRECTED: Use standard OIDC with server-side session isolation
    /// </summary>
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Add memory cache for session invalidation tracking
        services.AddMemoryCache();
        
        // CORRECTED: Use standard OIDC schemes - session isolation handled server-side
        const string adminCookieScheme = "AdminCookies";
        
        // Compute admin cookie name using the same convention as the server
        static string GetMrWhoCookieName(string clientId) => $".MrWho.{clientId}";
        var adminCookieName = GetMrWhoCookieName("mrwho_admin_web");
        
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
            ConfigureOpenIdConnect(options, configuration);
        });

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
    private static void ConfigureOpenIdConnect(OpenIdConnectOptions options, IConfiguration configuration)
    {
        var authConfig = configuration.GetSection("Authentication");
        
        options.Authority = authConfig.GetValue<string>("Authority") ?? "https://localhost:7113/";
        options.ClientId = authConfig.GetValue<string>("ClientId") ?? "mrwho_admin_web";
        options.ClientSecret = authConfig.GetValue<string>("ClientSecret") ?? "MrWhoAdmin2024!SecretKey";
        
        options.ResponseType = "code";
        options.SaveTokens = true; // CRITICAL: This saves tokens for API calls
        options.GetClaimsFromUserInfoEndpoint = true;
        
        // Production-friendly: allow configuring HTTPS metadata requirement via config (default true when using HTTPS Authority)
        var defaultRequireHttps = options.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        options.RequireHttpsMetadata = authConfig.GetValue("RequireHttpsMetadata", defaultRequireHttps);
        
        options.UsePkce = true; // Enable PKCE for better security

        // Set explicit callback paths for the admin web app (port 7257)
        options.CallbackPath = "/signin-oidc";
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        
        // IMPORTANT: Set the post sign-out redirect target to an anonymous page to avoid immediate re-login
        options.SignedOutRedirectUri = "/signed-out";
        
        // IMPORTANT: Set the correct remote signout path
        options.RemoteSignOutPath = "/signout-oidc";

        // Additional configuration for OpenIddict compatibility
        // Allow overriding metadata address (useful for Docker where the backchannel must reach the service by container name)
        var metadataAddress = authConfig.GetValue<string>("MetadataAddress");
        var resolvedMetadata = !string.IsNullOrWhiteSpace(metadataAddress)
            ? metadataAddress
            : $"{options.Authority.TrimEnd('/')}/.well-known/openid-configuration";
        options.MetadataAddress = resolvedMetadata;

        // Configure token refresh settings
        options.RefreshInterval = TimeSpan.FromMinutes(30); // Check for refresh every 30 minutes
        options.UseTokenLifetime = true; // Use the token's actual lifetime
        
        // CRITICAL: Skip unrecognized requests to prevent loops
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
        if (!string.IsNullOrWhiteSpace(metadataAddress))
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
                resolvedMetadata,
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
        options.Scope.Add("offline_access"); // CRITICAL: This scope is required for refresh tokens
        options.Scope.Add("api.read");  // Add API read scope
        options.Scope.Add("api.write"); // Add API write scope
        options.Scope.Add("mrwho.use"); // Add mrwho.use scope
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
                logger.LogInformation("?? ADMIN: Redirecting to identity provider with client_id: {ClientId}", context.ProtocolMessage.ClientId);
                logger.LogInformation("ADMIN OIDC Settings: Authority={Authority}, MetadataAddress={MetadataAddress}, HasCustomConfigManager={HasCM}",
                    context.Options.Authority, context.Options.MetadataAddress, context.Options.ConfigurationManager != null);

                // Force browser redirect to host-facing Authority regardless of discovery host
                var authority = context.Options.Authority?.TrimEnd('/') ?? string.Empty;
                if (!string.IsNullOrEmpty(authority))
                {
                    var desiredAuthorize = $"{authority}/connect/authorize";
                    if (!string.Equals(context.ProtocolMessage.IssuerAddress, desiredAuthorize, StringComparison.OrdinalIgnoreCase))
                    {
                        logger.LogInformation("ADMIN OIDC: Overriding IssuerAddress from {From} to {To}", context.ProtocolMessage.IssuerAddress, desiredAuthorize);
                        context.ProtocolMessage.IssuerAddress = desiredAuthorize;
                    }
                }
                return Task.CompletedTask;
            },
            
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("? ADMIN: Token validated successfully for user: {UserName}. Claims count: {ClaimsCount}", 
                    context.Principal?.Identity?.Name ?? "Unknown", context.Principal?.Claims?.Count() ?? 0);
                
                if (context.Principal?.Claims != null)
                {
                    foreach (var claim in context.Principal.Claims)
                    {
                        logger.LogDebug("ADMIN Token claim: {ClaimType} = {ClaimValue}", claim.Type, claim.Value);
                    }
                }
                
                return Task.CompletedTask;
            },

            OnUserInformationReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                var root = context.User.RootElement;
                logger.LogInformation("?? ADMIN: UserInfo received from endpoint. User document contains {PropertyCount} properties", 
                    root.EnumerateObject().Count());
                
                foreach (var property in root.EnumerateObject())
                {
                    logger.LogDebug("ADMIN UserInfo property: {PropertyName} = {PropertyValue}", property.Name, property.Value.ToString());
                }

                // OPTION 2 IMPLEMENTATION: dynamically project unmapped custom claims (e.g. myclaim) into the principal
                if (context.Principal?.Identity is ClaimsIdentity identity)
                {
                    try
                    {
                        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                        {
                            "sub","name","given_name","family_name","email","email_verified","preferred_username","phone_number","phone_number_verified","role","roles"
                        };

                        foreach (var prop in root.EnumerateObject())
                        {
                            if (known.Contains(prop.Name))
                            {
                                continue;
                            }
                            if (prop.Value.ValueKind == JsonValueKind.Null || prop.Value.ValueKind == JsonValueKind.Undefined)
                            {
                                continue;
                            }

                            bool AlreadyHas(string type, string value) => identity.HasClaim(c => c.Type == type && c.Value == value);
                            void AddStringClaim(string type, string value)
                            {
                                if (string.IsNullOrWhiteSpace(value)) return;
                                if (AlreadyHas(type, value)) return;
                                identity.AddClaim(new Claim(type, value));
                                logger.LogDebug("ADMIN UserInfo dynamic claim added: {Type} = {Value}", type, value);
                            }

                            switch (prop.Value.ValueKind)
                            {
                                case JsonValueKind.String:
                                    AddStringClaim(prop.Name, prop.Value.GetString()!);
                                    break;
                                case JsonValueKind.True:
                                case JsonValueKind.False:
                                    AddStringClaim(prop.Name, prop.Value.GetBoolean().ToString());
                                    break;
                                case JsonValueKind.Array:
                                    foreach (var elem in prop.Value.EnumerateArray())
                                    {
                                        if (elem.ValueKind == JsonValueKind.String)
                                            AddStringClaim(prop.Name, elem.GetString()!);
                                        else if (elem.ValueKind == JsonValueKind.True || elem.ValueKind == JsonValueKind.False)
                                            AddStringClaim(prop.Name, elem.GetBoolean().ToString());
                                    }
                                    break;
                                case JsonValueKind.Number:
                                    if (prop.Value.TryGetInt64(out var l)) AddStringClaim(prop.Name, l.ToString());
                                    else if (prop.Value.TryGetDouble(out var d)) AddStringClaim(prop.Name, d.ToString(System.Globalization.CultureInfo.InvariantCulture));
                                    break;
                                case JsonValueKind.Object:
                                    try
                                    {
                                        var json = prop.Value.GetRawText();
                                        AddStringClaim(prop.Name, json);
                                    }
                                    catch { }
                                    break;
                            }
                        }

                        logger.LogInformation("ADMIN UserInfo dynamic claim mapping complete. Total claims now: {Count}", identity.Claims.Count());
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "ADMIN: Exception while dynamically mapping UserInfo claims");
                    }
                }

                if (context.Principal?.Claims != null)
                {
                    foreach (var claim in context.Principal.Claims)
                    {
                        logger.LogDebug("ADMIN UserInfo final claim: {ClaimType} = {ClaimValue}", claim.Type, claim.Value);
                    }
                }

                return Task.CompletedTask;
            },
            
            OnTokenResponseReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("?? ADMIN: Token response received - Access Token: {HasAccessToken}, Refresh Token: {HasRefreshToken}", 
                    !string.IsNullOrEmpty(context.TokenEndpointResponse.AccessToken),
                    !string.IsNullOrEmpty(context.TokenEndpointResponse.RefreshToken));
                return Task.CompletedTask;
            },
            
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError("? ADMIN: Authentication failed: {Error} - {ErrorDescription}", 
                    context.Exception?.Message, context.Exception?.ToString());
                
                if (context.Exception is HttpRequestException httpEx && 
                    httpEx.Message.Contains("403") && 
                    httpEx.Message.Contains("Forbidden"))
                {
                    logger.LogWarning("?? ADMIN: UserInfo endpoint returned 403 Forbidden - this might be a temporary server issue");
                    return Task.CompletedTask;
                }
                
                var errorMessage = Uri.EscapeDataString(context.Exception?.Message ?? "Unknown error");
                context.Response.Redirect($"/auth/error?error={errorMessage}");
                context.HandleResponse();
                
                return Task.CompletedTask;
            },
            
            OnRemoteFailure = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError("?? ADMIN: Remote authentication failure: {Error}", context.Failure?.Message);
                
                if (context.Failure is HttpRequestException httpEx && 
                    httpEx.Message.Contains("403") && 
                    httpEx.Message.Contains("Forbidden"))
                {
                    logger.LogWarning("?? ADMIN: UserInfo endpoint returned 403 Forbidden during remote authentication");
                    return Task.CompletedTask;
                }
                
                var errorMessage = Uri.EscapeDataString(context.Failure?.Message ?? "Remote authentication failed");
                context.Response.Redirect($"/auth/error?error={errorMessage}");
                context.HandleResponse();
                
                return Task.CompletedTask;
            },
            
            OnAuthorizationCodeReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("?? ADMIN: Authorization code received, exchanging for tokens");
                return Task.CompletedTask;
            },
            
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("?? ADMIN: Redirecting to identity provider for sign out (server-side isolation via DynamicCookieService)");
                return Task.CompletedTask;
            },
            
            OnSignedOutCallbackRedirect = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("? ADMIN: Processing signed out callback redirect to: {RedirectUri}", 
                    context.Options.SignedOutRedirectUri);
                return Task.CompletedTask;
            }
        };
    }
}