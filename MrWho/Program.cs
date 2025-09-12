using MrWho.Extensions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using MrWho.Services;
using Microsoft.AspNetCore.HttpOverrides;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Client.SystemNetHttp;
using Microsoft.Extensions.Options;
using MrWho.Options;
using Microsoft.AspNetCore.Identity; // added for IdentityConstants

var builder = WebApplication.CreateBuilder(args);

AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
builder.Logging.AddFilter("OpenTelemetry", LogLevel.Debug);

builder.AddServiceDefaults();

// Bind global MrWho options from configuration
builder.Services.Configure<MrWhoOptions>(builder.Configuration.GetSection("MrWho"));
// Bind OIDC clients options for seeding (redirect URIs, secrets, etc.)
builder.Services.Configure<OidcClientsOptions>(builder.Configuration.GetSection("OidcClients"));

// Add services to the container using extension methods
builder.Services.AddControllersWithViews();
builder.AddMrWhoDatabase();

// Persist Data Protection keys in the application database so tokens/cookies are stable across restarts
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<MrWho.Data.ApplicationDbContext>();
// Must follow AddDataProtection()
builder.Services.AddMrWhoAntiforgery();

// Use new client-specific cookie configuration instead of standard Identity
builder.Services.AddMrWhoIdentityWithClientCookies();
builder.Services.AddMrWhoServices(); // includes registrar & hosted service
builder.Services.AddMrWhoClientCookies(builder.Configuration); // config-driven naming
// Updated to pass environment (Options 1 & 2 changes inside)
builder.Services.AddMrWhoOpenIddict(builder.Configuration, builder.Environment);

// Ensure Challenge() uses the Identity application cookie (redirects to login page)
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme; // critical for Challenge()
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
});

// OpenIddict client for upstream OIDC (moved to extension for consistency)
builder.Services.AddMrWhoOpenIddictClient(builder.Configuration, builder.Environment);

// Rate limiting
builder.Services.AddMrWhoRateLimiting(builder.Configuration);

builder.Services.AddMrWhoAuthorizationWithClientCookies();
builder.Services.AddMrWhoMediator();

builder.Services.AddScoped<ILogoutHelper, LogoutHelper>();
builder.Services.AddScoped<ILoginHelper, LoginHelper>();

var configuredCookieDomain = builder.Configuration["Cookie:Domain"];
var configuredRequireHttps = string.Equals(builder.Configuration["Cookie:RequireHttps"], "true", StringComparison.OrdinalIgnoreCase);

builder.Services.PostConfigureAll<CookieAuthenticationOptions>(options =>
{
    if (!builder.Environment.IsDevelopment() && !string.IsNullOrWhiteSpace(configuredCookieDomain))
    {
        options.Cookie.Domain = configuredCookieDomain;
    }
    // Always enforce Secure in production (Option 3). If explicitly requested insecure (dev), SameAsRequest is acceptable elsewhere.
    if (builder.Environment.IsDevelopment())
    {
        if (configuredRequireHttps)
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        }
    }
    else
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    }
});

// WebAuthn
var rpId = builder.Configuration["WebAuthn:RelyingPartyId"] ?? new Uri(builder.Configuration["OpenIddict:Issuer"] ?? "https://localhost:7113").Host;
var rpName = builder.Configuration["WebAuthn:RelyingPartyName"] ?? "MrWho";
var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "https://localhost:7113", "http://localhost:7113" };
var fromConfig = builder.Configuration.GetSection("WebAuthn:Origins").Get<string[]>() ?? Array.Empty<string>();
foreach (var o in fromConfig) if (!string.IsNullOrWhiteSpace(o)) origins.Add(o);
builder.Services.AddSingleton(new Fido2(new Fido2Configuration
{
    ServerDomain = rpId,
    ServerName = rpName,
    Origins = origins
}));

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".MrWho.Session";
    if (!builder.Environment.IsDevelopment() && !string.IsNullOrWhiteSpace(configuredCookieDomain))
    {
        options.Cookie.Domain = configuredCookieDomain;
    }
    if (!builder.Environment.IsDevelopment())
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    }
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireMfa", policy =>
    {
        policy.RequireAssertion(ctx =>
        {
            // Accept either TOTP-based MFA (amr=mfa) or WebAuthn/passkey (amr=fido2)
            return ctx.User?.Claims?.Any(c => c.Type == "amr" && (string.Equals(c.Value, "mfa", StringComparison.Ordinal) || string.Equals(c.Value, "fido2", StringComparison.Ordinal))) == true;
        });
    });
});

builder.Services.AddScoped<Microsoft.AspNetCore.Authentication.IClaimsTransformation, MrWho.Services.AmrClaimsTransformation>();

var app = builder.Build();

// Initialize database & seed (consolidated single entry point)
await app.InitializeDatabaseAsync();

// NOTE: Dynamic client cookie schemes now registered during InitializeDatabaseAsync()
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("MrWho OIDC Server starting...");

await app.ConfigureMrWhoPipelineWithClientCookiesAsync();

// Correlation middleware should be very early (after routing added in pipeline builder). If extension already built pipeline, insert here before auth endpoints.
app.Use(async (ctx, next) => await next()); // placeholder to keep relative position comment
app.UseMiddleware<MrWho.Middleware.CorrelationMiddleware>();

app.Run();