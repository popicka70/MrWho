using MrWhoAdmin.Web.Components;
using MrWhoAdmin.Web.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add services to the container using extension methods
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOutputCache();

// Configure services using extension methods
builder.Services.AddRadzenServices();
builder.Services.AddHttpServices();
builder.Services.AddApiServices(builder.Configuration);
builder.Services.AddAuthenticationServices(builder.Configuration);
builder.Services.AddAuthorizationServices();

var app = builder.Build();

// Configure middleware pipeline using extension methods
app.ConfigureMiddlewarePipeline();
app.ConfigureAuthenticationEndpoints();
app.ConfigureBlazorRouting();

app.MapDefaultEndpoints();

app.Run();
