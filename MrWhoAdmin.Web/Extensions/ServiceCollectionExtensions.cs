using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using MrWhoAdmin.Web.Services;
using MrWhoAdmin.Web.Extensions;
using Radzen;

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
        
        return services;
    }

    /// <summary>
    /// Adds API client services with authentication
    /// </summary>
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        var mrWhoApiBaseUrl = configuration.GetValue<string>("MrWhoApi:BaseUrl") ?? "https://localhost:7113/";

        // Register MrWho API clients with authentication
        services.AddHttpClient<IRealmsApiService, RealmsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IClientsApiService, ClientsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IClientTypesApiService, ClientTypesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IUsersApiService, UsersApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IRolesApiService, RolesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IScopesApiService, ScopesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IApiResourcesApiService, ApiResourcesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        services.AddHttpClient<IIdentityResourcesApiService, IdentityResourcesApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        // Add Sessions API service
        services.AddHttpClient<ISessionsApiService, SessionsApiService>(client =>
        {
            client.BaseAddress = new Uri(mrWhoApiBaseUrl);
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddHttpMessageHandler<AuthenticationDelegatingHandler>();

        return services;
    }

    /// <summary>
    /// Configures authentication services including OpenID Connect
    /// </summary>
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services, IConfiguration configuration)
    {
        // CRITICAL: Use client-specific cookie scheme to prevent session sharing
        const string adminCookieScheme = "AdminCookies";
        
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = adminCookieScheme; // Use client-specific scheme
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(adminCookieScheme, options => // Use client-specific scheme name
        {
            options.Cookie.Name = ".MrWho.Admin"; // Client-specific cookie name
            options.Cookie.Path = "/";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromHours(8); // Admin session timeout
            options.SlidingExpiration = true;
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
        })
        .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.SignInScheme = adminCookieScheme; // CRITICAL: Use client-specific scheme
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
        options.RequireHttpsMetadata = false; // Only for development
        options.UsePkce = true; // Enable PKCE for better security

        // Set explicit callback paths for the admin web app (port 7257)
        options.CallbackPath = "/signin-oidc";
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        
        // IMPORTANT: Set the correct remote signout path
        options.RemoteSignOutPath = "/signout-oidc";

        // Additional configuration for OpenIddict compatibility
        options.MetadataAddress = $"{options.Authority}.well-known/openid-configuration";

        // Configure token refresh settings
        options.RefreshInterval = TimeSpan.FromMinutes(30); // Check for refresh every 30 minutes
        options.UseTokenLifetime = true; // Use the token's actual lifetime
        
        // CRITICAL: Skip unrecognized requests to prevent loops
        options.SkipUnrecognizedRequests = true;

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
        // Force UserInfo endpoint call by removing ALL claims from ID token processing
        options.ClaimActions.Clear();
        options.ClaimActions.DeleteClaim("iss");
        options.ClaimActions.DeleteClaim("aud");
        options.ClaimActions.DeleteClaim("exp");
        options.ClaimActions.DeleteClaim("iat");
        options.ClaimActions.DeleteClaim("nonce");
        options.ClaimActions.DeleteClaim("at_hash");
        options.ClaimActions.DeleteClaim("azp");
        options.ClaimActions.DeleteClaim("oi_au_id");
        options.ClaimActions.DeleteClaim("oi_tbn_id");

        // Only map claims from UserInfo endpoint
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
                logger.LogInformation("Redirecting to identity provider: {Authority} with return URL: {ReturnUrl}", 
                    options.Authority, context.Properties.RedirectUri);
                return Task.CompletedTask;
            },
            
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Token validated successfully for user: {UserName}. Claims count: {ClaimsCount}", 
                    context.Principal?.Identity?.Name ?? "Unknown", context.Principal?.Claims?.Count() ?? 0);
                
                // Log the claims we have at this point
                if (context.Principal?.Claims != null)
                {
                    foreach (var claim in context.Principal.Claims)
                    {
                        logger.LogDebug("Token claim: {ClaimType} = {ClaimValue}", claim.Type, claim.Value);
                    }
                }
                
                return Task.CompletedTask;
            },

            OnUserInformationReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("UserInfo received from endpoint. User document contains {PropertyCount} properties", 
                    context.User.RootElement.EnumerateObject().Count());
                
                // Log what we received from UserInfo endpoint
                foreach (var property in context.User.RootElement.EnumerateObject())
                {
                    logger.LogDebug("UserInfo property: {PropertyName} = {PropertyValue}", property.Name, property.Value.ToString());
                }
                
                return Task.CompletedTask;
            },
            
            OnTokenResponseReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Token response received - Access Token: {HasAccessToken}, Refresh Token: {HasRefreshToken}", 
                    !string.IsNullOrEmpty(context.TokenEndpointResponse.AccessToken),
                    !string.IsNullOrEmpty(context.TokenEndpointResponse.RefreshToken));
                return Task.CompletedTask;
            },
            
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError("Authentication failed: {Error} - {ErrorDescription}", 
                    context.Exception?.Message, context.Exception?.ToString());
                
                // Handle authentication failures by redirecting to an error page
                var errorMessage = Uri.EscapeDataString(context.Exception?.Message ?? "Unknown error");
                context.Response.Redirect($"/auth-error?error={errorMessage}");
                context.HandleResponse();
                
                return Task.CompletedTask;
            },
            
            OnRemoteFailure = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError("Remote authentication failure: {Error}", context.Failure?.Message);
                
                // Handle remote failures by redirecting to an error page
                var errorMessage = Uri.EscapeDataString(context.Failure?.Message ?? "Remote authentication failed");
                context.Response.Redirect($"/auth-error?error={errorMessage}");
                context.HandleResponse();
                
                return Task.CompletedTask;
            },
            
            OnAuthorizationCodeReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Authorization code received, exchanging for tokens");
                return Task.CompletedTask;
            },
            
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Redirecting to identity provider for sign out");
                return Task.CompletedTask;
            },
            
            OnSignedOutCallbackRedirect = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogInformation("Processing signed out callback redirect to: {RedirectUri}", 
                    context.Options.SignedOutRedirectUri);
                return Task.CompletedTask;
            }
        };
    }
}