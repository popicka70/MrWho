using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MrWho.Data;
using MrWho.Options;
using MrWho.Shared.Authentication;

namespace MrWho.Services;

internal sealed class DynamicClientCookieRegistrar : IDynamicClientCookieRegistrar
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<DynamicClientCookieRegistrar> _logger;

    public DynamicClientCookieRegistrar(IServiceProvider sp, ILogger<DynamicClientCookieRegistrar> logger)
    {
        _sp = sp; _logger = logger;
    }

    public async Task RegisterAllAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _sp.CreateScope();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<MrWhoOptions>>().Value;
        var schemeProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var optionsCache = scope.ServiceProvider.GetRequiredService<IOptionsMonitorCache<CookieAuthenticationOptions>>();
        var dataProtection = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var mode = options.CookieSeparationMode;

        _logger.LogInformation("[CookieRegistrar] Init dynamic cookie schemes (Mode={Mode})", mode);

        if (mode == CookieSeparationMode.None)
        {
            _logger.LogInformation("[CookieRegistrar] Mode None - skip registration");
            return;
        }

        if (mode == CookieSeparationMode.ByRealm)
        {
            var realms = await db.Realms
                .Where(r => r.IsEnabled && r.Clients.Any(c => c.IsEnabled))
                .Select(r => r.Name)
                .ToListAsync(cancellationToken);
            foreach (var realm in realms)
            {
                var scheme = CookieSchemeNaming.BuildRealmScheme(realm);
                var cookie = CookieSchemeNaming.BuildRealmCookie(realm);
                await EnsureSchemeAsync(scheme, cookie, schemeProvider, optionsCache, dataProtection, cancellationToken);
            }
        }
        else
        {
            var clients = await db.Clients.Where(c => c.IsEnabled).Select(c => c.ClientId).ToListAsync(cancellationToken);
            foreach (var clientId in clients)
            {
                var scheme = CookieSchemeNaming.BuildClientScheme(clientId);
                var cookie = CookieSchemeNaming.BuildClientCookie(clientId);
                await EnsureSchemeAsync(scheme, cookie, schemeProvider, optionsCache, dataProtection, cancellationToken);
            }
        }

        _logger.LogInformation("[CookieRegistrar] Done registering dynamic cookie schemes");
    }

    private async Task EnsureSchemeAsync(
        string schemeName,
        string cookieName,
        IAuthenticationSchemeProvider schemeProvider,
        IOptionsMonitorCache<CookieAuthenticationOptions> cache,
        IDataProtectionProvider dp, CancellationToken ct)
    {
        var existing = await schemeProvider.GetSchemeAsync(schemeName);
        if (existing == null)
        {
            schemeProvider.AddScheme(new AuthenticationScheme(schemeName, schemeName, typeof(CookieAuthenticationHandler)));
            _logger.LogDebug("[CookieRegistrar] Added scheme {Scheme}", schemeName);
        }

        // Try to add options; if already exists TryAdd returns false and we skip
        var protector = dp.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", schemeName, "v2");
        var opts = new CookieAuthenticationOptions
        {
            Cookie = new CookieBuilder
            {
                Name = cookieName,
                HttpOnly = true,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                SameSite = SameSiteMode.Lax,
                Path = "/"
            },
            ExpireTimeSpan = TimeSpan.FromHours(8),
            SlidingExpiration = true,
            LoginPath = "/connect/login",
            LogoutPath = "/connect/logout",
            AccessDeniedPath = "/connect/access-denied",
            TicketDataFormat = new TicketDataFormat(protector)
        };
        if (cache.TryAdd(schemeName, opts))
        {
            _logger.LogDebug("[CookieRegistrar] Cached options for {Scheme} (Cookie={Cookie})", schemeName, cookieName);
        }
        else
        {
            _logger.LogDebug("[CookieRegistrar] Options already cached for {Scheme}", schemeName);
        }
    }
}
