using MrWho.ClientAuth;
using MrWho.ClientAuth.M2M; // added for M2M helpers

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Add HTTP client demos (base address of protected API)
var apiBase = new Uri(builder.Configuration["DemoApi:BaseUrl"] ?? "https://localhost:7162/");

// Machine-to-machine client (client_credentials) using MrWho.ClientAuth helpers
builder.Services.AddMrWhoClientCredentialsApi(
    name: "DemoApiM2M",
    baseAddress: apiBase,
    configure: opt =>
    {
        opt.Authority = builder.Configuration["Authentication:Authority"] ?? "https://localhost:7113";
        opt.ClientId = builder.Configuration["M2M:ClientId"] ?? "mrwho_demo_api_client";
        opt.ClientSecret = builder.Configuration["M2M:ClientSecret"] ?? "DemoApiClientSecret2025!"; // demo secret
        opt.Scopes = new[] { "api.read" };
        opt.AcceptAnyServerCertificate = builder.Environment.IsDevelopment();
    });

// User delegated token HttpClient (will attach currently authenticated user's access token if present)
builder.Services.AddMrWhoUserAccessTokenApi(
    name: "DemoApiUser",
    baseAddress: apiBase);

// Use the MrWho.ClientAuth NuGet to configure OIDC using only options
builder.Services.AddMrWhoAuthentication(options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"] ?? "https://localhost:7113";
    options.ClientId = builder.Configuration["Authentication:ClientId"] ?? "mrwho_demo_nuget";
    options.ClientSecret = builder.Configuration["Authentication:ClientSecret"]; // null for public
    options.SaveTokens = true;
    options.SignedOutCallbackPath = "/signout-callback-oidc";

    options.Scopes.Clear();
    options.Scopes.Add("openid");
    options.Scopes.Add("profile");
    options.Scopes.Add("email");
    options.Scopes.Add("roles");
    options.Scopes.Add("offline_access");
    // Add API scopes for delegated user call demonstration
    options.Scopes.Add("api.read");

    if (builder.Environment.IsDevelopment())
    {
        options.AllowSelfSignedCertificates = true;
    }
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok("OK"));

// Map library-provided login/logout/back-channel endpoints
app.MapMrWhoBackChannelLogoutEndpoint();
app.MapMrWhoLoginEndpoint();
app.MapMrWhoLogoutEndpoints();

// M2M demo endpoint: obtain token + call WeatherForecast via named M2M client
app.MapGet("/demo/m2m-call", async (IHttpClientFactory factory) =>
{
    var client = factory.CreateClient("DemoApiM2M");
    var resp = await client.GetAsync("WeatherForecast");
    var body = await resp.Content.ReadAsStringAsync();
    return Results.Json(new { status = (int)resp.StatusCode, ok = resp.IsSuccessStatusCode, body });
});

// Delegated user call (requires auth for clarity)
app.MapGet("/demo/user-call", async (IHttpClientFactory factory, HttpContext ctx) =>
{
    if (ctx.User?.Identity?.IsAuthenticated != true)
    {
        return Results.Unauthorized();
    }
    var client = factory.CreateClient("DemoApiUser");
    var resp = await client.GetAsync("WeatherForecast");
    var body = await resp.Content.ReadAsStringAsync();
    return Results.Json(new { status = (int)resp.StatusCode, ok = resp.IsSuccessStatusCode, body });
}).RequireAuthorization();

app.MapRazorPages();

app.Run();
