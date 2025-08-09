using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Extensions;
using MrWhoAdmin.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container using extension methods
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

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

// API Services are already registered in AddApiServices() method above

var app = builder.Build();

// Configure middleware pipeline using extension methods
app.ConfigureMiddlewarePipeline();
app.ConfigureAuthenticationEndpoints();

// Map controllers for token refresh and back-channel logout
app.MapControllers();

app.ConfigureBlazorRouting();

app.MapDefaultEndpoints();

app.Run();
