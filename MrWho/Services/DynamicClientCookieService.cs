using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace MrWho.Services;

/// <summary>
/// Service that dynamically registers authentication schemes for database-configured clients
/// This provides true runtime registration of client-specific cookie authentication schemes
/// </summary>
public class DynamicClientCookieService : IHostedService
{
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IOptionsMonitorCache<CookieAuthenticationOptions> _optionsCache;
    private readonly ILogger<DynamicClientCookieService> _logger;

    public DynamicClientCookieService(
        IServiceScopeFactory serviceScopeFactory,
        IAuthenticationSchemeProvider schemeProvider,
        IOptionsMonitorCache<CookieAuthenticationOptions> optionsCache,
        ILogger<DynamicClientCookieService> logger)
    {
        _serviceScopeFactory = serviceScopeFactory;
        _schemeProvider = schemeProvider;
        _optionsCache = optionsCache;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("?? Starting dynamic client cookie registration...");

        try
        {
            using var scope = _serviceScopeFactory.CreateScope();
            var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();
            var authSchemeProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
            var cookieConfigService = scope.ServiceProvider.GetRequiredService<IClientCookieConfigurationService>();

            // Load all enabled clients from database
            var enabledClients = await oidcClientService.GetEnabledClientsAsync();
            var registeredCount = 0;
            
            foreach (var client in enabledClients)
            {
                var schemeName = $"Identity.Application.{client.ClientId}";
                var cookieName = $".MrWho.{client.Name?.Replace(" ", "").Replace("-", "")}";
                
                // Check if scheme already exists (avoid duplicates with static registration)
                var existingScheme = await authSchemeProvider.GetSchemeAsync(schemeName);
                if (existingScheme != null)
                {
                    _logger.LogDebug("?? Scheme {SchemeName} already exists (static registration), skipping dynamic registration", schemeName);
                    continue;
                }

                // Additional check: verify this client doesn't have static configuration
                if (cookieConfigService.HasStaticConfiguration(client.ClientId))
                {
                    _logger.LogDebug("?? Client {ClientId} has static cookie configuration, skipping dynamic registration", client.ClientId);
                    continue;
                }

                try
                {
                    // Create and register the authentication scheme with full configuration
                    var scheme = new AuthenticationScheme(schemeName, schemeName, typeof(CookieAuthenticationHandler));
                    
                    // Register the scheme
                    authSchemeProvider.AddScheme(scheme);

                    // Create and cache the options for this scheme
                    var cookieOptions = CreateCookieOptions(client, cookieName);
                    _optionsCache.TryAdd(schemeName, cookieOptions);

                    registeredCount++;
                    _logger.LogInformation("? Dynamically registered authentication scheme: {ClientId} ? {CookieName} (Scheme: {SchemeName})", 
                        client.ClientId, cookieName, schemeName);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "? Failed to register scheme for client {ClientId}", client.ClientId);
                }
            }

            _logger.LogInformation("?? Dynamic client cookie registration completed. Registered: {RegisteredCount}/{TotalCount} clients", 
                registeredCount, enabledClients.Count());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "? Failed to complete dynamic client cookie registration");
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("?? Stopping dynamic client cookie service...");
        return Task.CompletedTask;
    }

    private static CookieAuthenticationOptions CreateCookieOptions(Models.Client client, string cookieName)
    {
        return new CookieAuthenticationOptions
        {
            Cookie = new CookieBuilder
            {
                Name = cookieName,
                HttpOnly = true,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                SameSite = SameSiteMode.Lax,
                Path = "/",
                Domain = null // Same domain only
            },
            ExpireTimeSpan = TimeSpan.FromHours(GetSessionTimeoutHours(client)),
            SlidingExpiration = true,
            LoginPath = "/connect/login",
            LogoutPath = "/connect/logout",
            AccessDeniedPath = "/connect/access-denied",
            
            // Configure events for debugging and logging
            Events = new CookieAuthenticationEvents
            {
                OnSigningIn = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("?? Dynamic cookie sign-in for client: {ClientId}", client.ClientId);
                    return Task.CompletedTask;
                },
                OnSigningOut = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("?? Dynamic cookie sign-out for client: {ClientId}", client.ClientId);
                    return Task.CompletedTask;
                },
                OnRedirectToAccessDenied = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogWarning("?? REDIRECTING TO ACCESS DENIED for dynamic client {ClientId}: RedirectUri={RedirectUri}, ReturnUrl={ReturnUrl}", 
                        client.ClientId, context.RedirectUri, context.Request.Query["ReturnUrl"].ToString());
                    return Task.CompletedTask;
                },
                OnValidatePrincipal = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("?? Validating principal for dynamic client {ClientId}: IsAuthenticated={IsAuthenticated}, Name={Name}", 
                        client.ClientId, context.Principal?.Identity?.IsAuthenticated, context.Principal?.Identity?.Name);
                    return Task.CompletedTask;
                }
            }
        };
    }

    private static int GetSessionTimeoutHours(Models.Client client)
    {
        // Use the new database-driven session timeout with fallback to hardcoded logic
        return client.GetEffectiveSessionTimeoutHours();
    }
}

/// <summary>
/// Custom options configurator for dynamically registered cookie schemes
/// This ensures that the options are properly configured when the authentication system requests them
/// </summary>
public class DynamicCookieOptionsConfigurator : IConfigureNamedOptions<CookieAuthenticationOptions>
{
    private readonly ILogger<DynamicCookieOptionsConfigurator> _logger;

    public DynamicCookieOptionsConfigurator(ILogger<DynamicCookieOptionsConfigurator> logger)
    {
        _logger = logger;
    }

    public void Configure(CookieAuthenticationOptions options)
    {
        // Default configuration for all cookie schemes
    }

    public void Configure(string? name, CookieAuthenticationOptions options)
    {
        if (string.IsNullOrEmpty(name) || !name.StartsWith("Identity.Application."))
        {
            return;
        }

        // This method is called when the authentication system needs options for a dynamic scheme
        _logger.LogDebug("?? Configuring dynamic cookie options for scheme: {SchemeName}", name);
        
        // The options should already be configured by DynamicClientCookieService
        // This is a safety net in case they weren't properly cached
        if (options.Cookie.Name == null)
        {
            _logger.LogWarning("?? Cookie options not properly configured for scheme {SchemeName}, applying defaults", name);
            
            // Extract client ID from scheme name and apply default configuration
            var clientId = name.Replace("Identity.Application.", "");
            options.Cookie.Name = $".MrWho.{clientId}";
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.LoginPath = "/connect/login";
            options.LogoutPath = "/connect/logout";
            options.AccessDeniedPath = "/connect/access-denied";
        }
    }
}