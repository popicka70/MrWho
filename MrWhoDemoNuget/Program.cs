using MrWho.ClientAuth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Use the MrWho.ClientAuth NuGet to configure OIDC using only options
builder.Services.AddMrWhoAuthentication(options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"] ?? "https://localhost:7113";
    options.ClientId = builder.Configuration["Authentication:ClientId"] ?? "mrwho_demo_nuget";
    options.ClientSecret = builder.Configuration["Authentication:ClientSecret"]; // null for public

    options.Scopes.Clear();
    options.Scopes.Add("openid");
    options.Scopes.Add("profile");
    options.Scopes.Add("email");
    options.Scopes.Add("roles");
    options.Scopes.Add("offline_access");

    // Optional: trust self-signed in dev
    if (builder.Environment.IsDevelopment())
    {
        options.AllowSelfSignedCertificates = true;
    }

    // Optional scopes tweak (defaults already include openid, profile, email, roles, offline_access, api.read, api.write)
    // options.Scopes.Add("custom.scope");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
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

// Health endpoint for Aspire
app.MapGet("/health", () => Results.Ok("OK"));

// Map the back-channel logout endpoint provided by MrWho.ClientAuth
app.MapMrWhoBackChannelLogoutEndpoint();

app.MapRazorPages();

app.Run();
