using MrWho.Extensions;
using MrWho.Services;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add services to the container using extension methods
builder.Services.AddControllersWithViews();
builder.Services.AddMrWhoAntiforgery();
builder.AddMrWhoDatabase();

// Use new client-specific cookie configuration instead of standard Identity
builder.Services.AddMrWhoIdentityWithClientCookies();
builder.Services.AddMrWhoServices();
builder.Services.AddMrWhoClientCookies(); // Add client-specific cookies
builder.Services.AddMrWhoOpenIddict();
builder.Services.AddMrWhoAuthorizationWithClientCookies(); // Use authorization with client cookie support

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

// Business Logic Services
// Registration is handled in AddMrWhoServices() extension method

// ensure services are registered
builder.Services.AddSingleton<IQrCodeService, QrCodeService>();
builder.Services.AddScoped<Microsoft.AspNetCore.Authentication.IClaimsTransformation, MrWho.Services.AmrClaimsTransformation>();

var app = builder.Build();

// Configure the HTTP request pipeline using the new client-cookie-aware method
await app.ConfigureMrWhoPipelineWithClientCookiesAsync();
app.AddMrWhoEndpoints();
app.AddMrWhoDebugEndpoints();

app.Run();