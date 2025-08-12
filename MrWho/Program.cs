using MrWho.Extensions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using MrWho.Services;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container using extension methods
builder.Services.AddControllersWithViews();
builder.Services.AddMrWhoAntiforgery();
builder.AddMrWhoDatabase();

// Persist Data Protection keys in the application database so tokens/cookies are stable across restarts
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<MrWho.Data.ApplicationDbContext>();

// Use new client-specific cookie configuration instead of standard Identity
builder.Services.AddMrWhoIdentityWithClientCookies();
builder.Services.AddMrWhoServices(); // This now includes device management services
builder.Services.AddMrWhoClientCookies(); // Add client-specific cookies
builder.Services.AddMrWhoOpenIddict();
builder.Services.AddMrWhoAuthorizationWithClientCookies(); // Use authorization with client cookie support
builder.Services.AddMrWhoMediator(); // Lightweight mediator + endpoint handlers

// Honor X-Forwarded-* headers from the hosting platform (Railway/reverse proxies)
// so Request.Scheme becomes https and OpenIddict doesn't reject requests.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Trust all proxy networks by default (Railway manages TLS). If you have fixed proxies,
    // replace with explicit KnownNetworks/KnownProxies entries.
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Add session support for client tracking
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".MrWho.Session";
});

// Authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireMfa", policy =>
        policy.RequireClaim("amr", "mfa"));
});

// Register claims transformation service
builder.Services.AddScoped<Microsoft.AspNetCore.Authentication.IClaimsTransformation, MrWho.Services.AmrClaimsTransformation>();

var app = builder.Build();

// Log current environment information
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("?? MrWho OIDC Server starting up...");
logger.LogInformation("?? Environment: {Environment}", app.Environment.EnvironmentName);
logger.LogInformation("?? Application Name: {ApplicationName}", app.Environment.ApplicationName);
logger.LogInformation("?? Content Root: {ContentRoot}", app.Environment.ContentRootPath);
logger.LogInformation("?? Web Root: {WebRoot}", app.Environment.WebRootPath);
logger.LogInformation("?? Is Development: {IsDevelopment}", app.Environment.IsDevelopment());
logger.LogInformation("?? Is Production: {IsProduction}", app.Environment.IsProduction());
logger.LogInformation("?? Is Staging: {IsStaging}", app.Environment.IsStaging());
logger.LogInformation("?? Device Management: Enhanced QR login with persistent device pairing enabled");

// Configure the HTTP request pipeline using the new client-cookie-aware method
await app.ConfigureMrWhoPipelineWithClientCookiesAsync();
app.AddMrWhoEndpoints();
app.AddMrWhoDebugEndpoints();

app.Run();