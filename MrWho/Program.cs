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

var builder = WebApplication.CreateBuilder(args);

AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
builder.Logging.AddFilter("OpenTelemetry", LogLevel.Debug);

builder.AddServiceDefaults();

// Bind global MrWho options from configuration
builder.Services.Configure<MrWhoOptions>(builder.Configuration.GetSection("MrWho"));

// Add services to the container using extension methods
builder.Services.AddControllersWithViews();
builder.Services.AddMrWhoAntiforgery();
builder.AddMrWhoDatabase();

// Persist Data Protection keys in the application database so tokens/cookies are stable across restarts
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<MrWho.Data.ApplicationDbContext>();

// Use new client-specific cookie configuration instead of standard Identity
builder.Services.AddMrWhoIdentityWithClientCookies();
builder.Services.AddMrWhoServices(); // includes registrar & hosted service
builder.Services.AddMrWhoClientCookies(builder.Configuration); // config-driven naming
builder.Services.AddMrWhoOpenIddict(builder.Configuration);

// OpenIddict client for upstream OIDC
builder.Services.AddOpenIddict()
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();
        options.SetRedirectionEndpointUris("/connect/external/callback");
        options.SetPostLogoutRedirectionEndpointUris("/connect/external/signout-callback");
        if (builder.Environment.IsDevelopment())
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

builder.Services.AddSingleton<IConfigureOptions<OpenIddictClientOptions>, ExternalIdpClientOptionsConfigurator>();
builder.Services.AddSingleton<IPostConfigureOptions<OpenIddictClientOptions>, OpenIddictClientOptionsPostConfigurator>();

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
    if (configuredRequireHttps)
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
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
    if (configuredRequireHttps)
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
    }
});

var rlSection = builder.Configuration.GetSection("RateLimiting");
int loginPerHour = rlSection.GetValue<int?>("LoginPerHour") ?? 20;
int registerPerHour = rlSection.GetValue<int?>("RegisterPerHour") ?? 5;
int tokenPerHour = rlSection.GetValue<int?>("TokenPerHour") ?? 60;
int authorizePerHour = rlSection.GetValue<int?>("AuthorizePerHour") ?? 120;
int userInfoPerHour = rlSection.GetValue<int?>("UserInfoPerHour") ?? 240;

static string GetIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

builder.Services.AddRateLimiter(options =>
{
    options.OnRejected = (context, token) => { context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests; return ValueTask.CompletedTask; };
    options.AddPolicy("rl.login", ctx => RateLimitPartition.GetFixedWindowLimiter(GetIp(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = Math.Max(1, loginPerHour), Window = TimeSpan.FromHours(1), QueueProcessingOrder = QueueProcessingOrder.OldestFirst, QueueLimit = 0, AutoReplenishment = true }));
    options.AddPolicy("rl.register", ctx => RateLimitPartition.GetFixedWindowLimiter(GetIp(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = Math.Max(1, registerPerHour), Window = TimeSpan.FromHours(1), QueueProcessingOrder = QueueProcessingOrder.OldestFirst, QueueLimit = 0, AutoReplenishment = true }));
    options.AddPolicy("rl.token", ctx => RateLimitPartition.GetFixedWindowLimiter(GetIp(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = Math.Max(1, tokenPerHour), Window = TimeSpan.FromHours(1), QueueProcessingOrder = QueueProcessingOrder.OldestFirst, QueueLimit = 0, AutoReplenishment = true }));
    options.AddPolicy("rl.authorize", ctx => RateLimitPartition.GetFixedWindowLimiter(GetIp(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = Math.Max(1, authorizePerHour), Window = TimeSpan.FromHours(1), QueueProcessingOrder = QueueProcessingOrder.OldestFirst, QueueLimit = 0, AutoReplenishment = true }));
    options.AddPolicy("rl.userinfo", ctx => RateLimitPartition.GetFixedWindowLimiter(GetIp(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = Math.Max(1, userInfoPerHour), Window = TimeSpan.FromHours(1), QueueProcessingOrder = QueueProcessingOrder.OldestFirst, QueueLimit = 0, AutoReplenishment = true }));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireMfa", policy => policy.RequireClaim("amr", "mfa"));
});

builder.Services.AddScoped<Microsoft.AspNetCore.Authentication.IClaimsTransformation, MrWho.Services.AmrClaimsTransformation>();

var app = builder.Build();

// NOTE: Dynamic client cookie schemes now registered after database seeding inside InitializeDatabaseAsync()
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("MrWho OIDC Server starting...");

await app.ConfigureMrWhoPipelineWithClientCookiesAsync();
app.Run();