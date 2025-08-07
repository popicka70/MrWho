using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Extensions;
using MrWhoAdmin.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container using extension methods
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add MVC controllers for token refresh endpoint
builder.Services.AddControllers();

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

// Map controllers for token refresh
app.MapControllers();

app.ConfigureBlazorRouting();

app.MapDefaultEndpoints();

app.Run();
