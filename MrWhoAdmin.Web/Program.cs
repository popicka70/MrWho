using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Extensions;
using MrWhoAdmin.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container using extension methods
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents(options =>
    {
        // CRITICAL: Configure circuit options to prevent disposal issues
        options.DetailedErrors = builder.Environment.IsDevelopment();
        options.DisconnectedCircuitMaxRetained = 100;
        options.DisconnectedCircuitRetentionPeriod = TimeSpan.FromMinutes(3);
        options.JSInteropDefaultCallTimeout = TimeSpan.FromMinutes(1);
        options.MaxBufferedUnacknowledgedRenderBatches = 10;
    });

// Add MVC controllers for token refresh endpoint and back-channel logout
builder.Services.AddControllers();

// CRITICAL: Add distributed memory cache for session support
builder.Services.AddDistributedMemoryCache();

// Add session support for logout notifications
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".MrWho.AdminWeb.Session";
});

builder.Services.AddOutputCache();

// Configure services using extension methods
builder.Services.AddRadzenServices();
builder.Services.AddHttpServices();
builder.Services.AddApiServices(builder.Configuration);
builder.Services.AddAuthenticationServices(builder.Configuration);
builder.Services.AddAuthorizationServices();
builder.Services.AddScoped<AuditApiService>();

// Add Blazor Server circuit event handling for better error handling
builder.Services.AddSingleton<Microsoft.AspNetCore.Components.Server.Circuits.CircuitHandler, CircuitHandlerService>();

// API Services are already registered in AddApiServices() method above

var app = builder.Build();

// Log current environment information
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("MrWho Admin Web starting up...");
logger.LogInformation("Environment: {Environment}", app.Environment.EnvironmentName);
logger.LogInformation("Application Name: {ApplicationName}", app.Environment.ApplicationName);
logger.LogInformation("Content Root: {ContentRoot}", app.Environment.ContentRootPath);
logger.LogInformation("Web Root: {WebRoot}", app.Environment.WebRootPath);
logger.LogInformation("Is Development: {IsDevelopment}", app.Environment.IsDevelopment());
logger.LogInformation("Is Production: {IsProduction}", app.Environment.IsProduction());
logger.LogInformation("Is Staging: {IsStaging}", app.Environment.IsStaging());

// Configure middleware pipeline using extension methods
app.ConfigureMiddlewarePipeline();
app.ConfigureAuthenticationEndpoints();

// Map controllers for token refresh and back-channel logout
app.MapControllers();

app.ConfigureBlazorRouting();

app.MapDefaultEndpoints();

app.Run();
