using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection; // ensure data protection is available
using Microsoft.AspNetCore.Identity; // for IdentityConstants
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Shared.Authentication; // use centralized naming

namespace MrWho.Services;

/// <summary>
/// Service that dynamically registers authentication schemes for database-configured clients or realms
/// This provides runtime registration of cookie authentication schemes based on the global separation mode
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
        _logger.LogInformation("Starting dynamic cookie scheme registration...");

        try
        {
            using var scope = _serviceScopeFactory.CreateScope();
            var config = scope.ServiceProvider.GetRequiredService<IOptions<MrWhoOptions>>().Value;
            var mode = config.CookieSeparationMode;

            if (mode == CookieSeparationMode.None)
            {
                _logger.LogInformation("CookieSeparationMode=None. Skipping dynamic scheme registration.");
                return;
            }

            if (mode == CookieSeparationMode.ByRealm)
            {
                await RegisterRealmSchemesAsync(scope, cancellationToken);
                return;
            }

            // Default/ByClient registration path
            await RegisterClientSchemesAsync(scope, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to complete dynamic cookie scheme registration");
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping dynamic client cookie service...");
        return Task.CompletedTask;
    }

    private async Task RegisterClientSchemesAsync(IServiceScope scope, CancellationToken cancellationToken)
    {
        var oidcClientService = scope.ServiceProvider.GetRequiredService<IOidcClientService>();
        var authSchemeProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var dataProtectionProvider = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();

        var enabledClients = await oidcClientService.GetEnabledClientsAsync();
        var registeredCount = 0;

        foreach (var client in enabledClients)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var schemeName = CookieSchemeNaming.BuildClientScheme(client.ClientId);
            var cookieName = CookieSchemeNaming.BuildClientCookie(client.ClientId);

            var existingScheme = await authSchemeProvider.GetSchemeAsync(schemeName);
            if (existingScheme != null)
            {
                _logger.LogDebug("Scheme {SchemeName} already exists (static registration), skipping dynamic registration", schemeName);
                continue;
            }

            try
            {
                var scheme = new AuthenticationScheme(schemeName, schemeName, typeof(CookieAuthenticationHandler));
                authSchemeProvider.AddScheme(scheme);

                var cookieOptions = CreateClientCookieOptions(client, cookieName);

                // Ensure cookies can be unprotected by configuring a TicketDataFormat using Data Protection
                var protector = dataProtectionProvider.CreateProtector(
                    "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
                    schemeName,
                    "v2");
                cookieOptions.TicketDataFormat = new TicketDataFormat(protector);

                _optionsCache.TryAdd(schemeName, cookieOptions);

                registeredCount++;
                _logger.LogInformation("Registered client scheme: {ClientId} -> {CookieName} (Scheme: {SchemeName})", 
                    client.ClientId, cookieName, schemeName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register scheme for client {ClientId}", client.ClientId);
            }
        }

        _logger.LogInformation("Dynamic client cookie registration completed. Registered: {RegisteredCount}/{TotalCount} clients", 
            registeredCount, enabledClients.Count());
    }

    private async Task RegisterRealmSchemesAsync(IServiceScope scope, CancellationToken cancellationToken)
    {
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var authSchemeProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var dataProtectionProvider = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();

        // Get enabled realms that have at least one enabled client
        var realms = await db.Realms
            .Where(r => r.IsEnabled)
            .Select(r => new { Realm = r, HasClients = r.Clients.Any(c => c.IsEnabled) })
            .ToListAsync(cancellationToken);

        var registered = 0;
        foreach (var item in realms)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!item.HasClients)
            {
                continue;
            }

            var realm = item.Realm;
            var schemeName = CookieSchemeNaming.BuildRealmScheme(realm.Name);
            var cookieName = CookieSchemeNaming.BuildRealmCookie(realm.Name);

            var existingScheme = await authSchemeProvider.GetSchemeAsync(schemeName);
            if (existingScheme != null)
            {
                _logger.LogDebug("Realm scheme {SchemeName} already exists, skipping", schemeName);
                continue;
            }

            try
            {
                var scheme = new AuthenticationScheme(schemeName, schemeName, typeof(CookieAuthenticationHandler));
                authSchemeProvider.AddScheme(scheme);

                var cookieOptions = CreateRealmCookieOptions(realm, cookieName);

                // Ensure cookies can be unprotected by configuring a TicketDataFormat using Data Protection
                var protector = dataProtectionProvider.CreateProtector(
                    "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
                    schemeName,
                    "v2");
                cookieOptions.TicketDataFormat = new TicketDataFormat(protector);

                _optionsCache.TryAdd(schemeName, cookieOptions);

                registered++;
                _logger.LogInformation("Registered realm scheme: {RealmName} -> {CookieName} (Scheme: {SchemeName})", 
                    realm.Name, cookieName, schemeName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register scheme for realm {RealmName}", realm.Name);
            }
        }

        _logger.LogInformation("Dynamic realm cookie registration completed. Registered: {RegisteredCount} realms", registered);
    }

    private static CookieAuthenticationOptions CreateClientCookieOptions(Models.Client client, string cookieName)
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
                Domain = null
            },
            ExpireTimeSpan = TimeSpan.FromHours(GetSessionTimeoutHours(client)),
            SlidingExpiration = true,
            LoginPath = "/connect/login",
            LogoutPath = "/connect/logout",
            AccessDeniedPath = "/connect/access-denied",
            Events = new CookieAuthenticationEvents
            {
                OnSigningIn = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("Dynamic cookie sign-in for client: {ClientId}", client.ClientId);
                    return Task.CompletedTask;
                },
                OnSigningOut = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("Dynamic cookie sign-out for client: {ClientId}", client.ClientId);
                    return Task.CompletedTask;
                },
                OnRedirectToAccessDenied = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogWarning("REDIRECTING TO ACCESS DENIED for dynamic client {ClientId}: RedirectUri={RedirectUri}, ReturnUrl={ReturnUrl}", 
                        client.ClientId, context.RedirectUri, context.Request.Query["ReturnUrl"].ToString());
                    return Task.CompletedTask;
                },
                OnValidatePrincipal = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("Validating principal for dynamic client {ClientId}: IsAuthenticated={IsAuthenticated}, Name={Name}", 
                        client.ClientId, context.Principal?.Identity?.IsAuthenticated, context.Principal?.Identity?.Name);
                    return Task.CompletedTask;
                }
            }
        };
    }

    private static CookieAuthenticationOptions CreateRealmCookieOptions(Models.Realm realm, string cookieName)
    {
        return new CookieAuthenticationOptions
        {
            Cookie = new CookieBuilder
            {
                Name = cookieName,
                HttpOnly = true,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                SameSite = realm.GetEffectiveCookieSameSitePolicy(),
                Path = "/",
                Domain = null
            },
            ExpireTimeSpan = TimeSpan.FromHours(realm.DefaultSessionTimeoutHours > 0 ? realm.DefaultSessionTimeoutHours : 8),
            SlidingExpiration = realm.DefaultUseSlidingSessionExpiration,
            LoginPath = "/connect/login",
            LogoutPath = "/connect/logout",
            AccessDeniedPath = "/connect/access-denied",
            Events = new CookieAuthenticationEvents
            {
                OnSigningIn = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("Dynamic cookie sign-in for realm: {Realm}", realm.Name);
                    return Task.CompletedTask;
                },
                OnSigningOut = context =>
                {
                    var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<DynamicClientCookieService>>();
                    logger.LogDebug("Dynamic cookie sign-out for realm: {Realm}", realm.Name);
                    return Task.CompletedTask;
                }
            }
        };
    }

    private static int GetSessionTimeoutHours(Models.Client client)
    {
        return client.GetEffectiveSessionTimeoutHours();
    }

    private static string Sanitize(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "Default";
        Span<char> buffer = stackalloc char[name.Length];
        var i = 0;
        foreach (var ch in name)
        {
            buffer[i++] = char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-' ? ch : '_';
        }
        return new string(buffer[..i]);
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
        // Handle both the default Identity scheme and dynamic client schemes
        if (string.IsNullOrEmpty(name) || 
            (!name.StartsWith("Identity.Application") && 
             !name.Equals(IdentityConstants.ApplicationScheme, StringComparison.Ordinal)))
        {
            return;
        }

        _logger.LogDebug("Configuring dynamic cookie options for scheme: {SchemeName}", name);

        // Check if this is the default Identity scheme that needs basic configuration
        if (name.Equals(IdentityConstants.ApplicationScheme, StringComparison.Ordinal))
        {
            // Default Identity scheme should already be configured by ConfigureApplicationCookie
            // Only ensure critical properties are set if they're missing
            if (options.Cookie.Name == null)
            {
                _logger.LogDebug("Setting default cookie name for Identity.Application scheme");
                options.Cookie.Name = CookieSchemeNaming.DefaultCookieName;
            }
            
            // Ensure TicketDataFormat is configured for data protection
            if (options.TicketDataFormat == null)
            {
                _logger.LogWarning("TicketDataFormat is null for default Identity scheme, this may cause authentication issues");
            }
            
            return;
        }

        // Handle dynamic client schemes (Identity.Application.{clientId})
        if (name.StartsWith("Identity.Application.") && options.Cookie.Name == null)
        {
            _logger.LogWarning("Cookie options not properly configured for scheme {SchemeName}, applying defaults", name);

            // Extract key from scheme name and apply default configuration
            var key = name.Replace("Identity.Application.", "");
            options.Cookie.Name = CookieSchemeNaming.BuildClientCookie(key);
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = SameSiteMode.None; // Important for cross-site redirect/logout flows
            options.LoginPath = "/connect/login";
            options.LogoutPath = "/connect/logout";
            options.AccessDeniedPath = "/connect/access-denied";
        }
        else if (name.StartsWith("Identity.Application."))
        {
            // Ensure SameSite is compatible even if name was set elsewhere
            if (options.Cookie.SameSite != SameSiteMode.None)
            {
                options.Cookie.SameSite = SameSiteMode.None;
            }
        }
    }
}