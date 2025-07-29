using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.ApiService.Data;
using MrWho.ApiService.Models;
using MrWho.ApiService.Services;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Add service defaults & Aspire client integrations.
builder.AddServiceDefaults();

// Add SQL Server
builder.AddSqlServerDbContext<ApplicationDbContext>("MrWhoDb");

// Add Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure Identity options
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
});

// Add OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        // Set authorization and token endpoint URIs
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");

        // Enable the authorization code, password and client credentials flows
        options.AllowAuthorizationCodeFlow()
               .AllowPasswordFlow()
               .AllowClientCredentialsFlow()
               .AllowRefreshTokenFlow();

        // Mark the "email", "profile" and "roles" scopes as supported scopes
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        // Register claims
        options.RegisterClaims(Claims.Email, Claims.Name, Claims.PreferredUsername, 
                              Claims.GivenName, Claims.FamilyName, Claims.Role);

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Enable Authorization Server passthrough for authorization endpoint
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Add Razor Pages and MVC for login UI
builder.Services.AddRazorPages();
builder.Services.AddMvc();

// Add authentication
builder.Services.AddAuthentication();

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddScoped<IUserService, UserService>();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();
app.MapDefaultEndpoints();

// Apply database migrations and seed initial data
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
    
    try
    {
        logger.LogInformation("Applying database migrations...");
        
        // Apply any pending migrations
        await context.Database.MigrateAsync();
        
        logger.LogInformation("Database migrations applied successfully.");
        
        // Seed OIDC clients
        logger.LogInformation("Checking for OIDC client configurations...");
        
        // Create server-to-server client (existing)
        if (await applicationManager.FindByClientIdAsync("mrwho-client") == null)
        {
            logger.LogInformation("Creating server-to-server OIDC client...");
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mrwho-client",
                ClientSecret = "mrwho-secret",
                DisplayName = "MrWho Client Application",
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.Password,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                }
            });
            logger.LogInformation("Server-to-server OIDC client created successfully.");
        }
        
        // Create web application client (new for web flow)
        if (await applicationManager.FindByClientIdAsync("mrwho-web-client") == null)
        {
            logger.LogInformation("Creating web application OIDC client...");
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mrwho-web-client",
                ClientSecret = "mrwho-web-secret",
                DisplayName = "MrWho Web Application",
                RedirectUris =
                {
                    new Uri("https://localhost:5000/signin-oidc"),
                    new Uri("https://localhost:5001/signin-oidc"),
                    new Uri("http://localhost:5000/signin-oidc"),
                    new Uri("http://localhost:5001/signin-oidc")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:5000/signout-oidc"),
                    new Uri("https://localhost:5001/signout-oidc"),
                    new Uri("http://localhost:5000/signout-oidc"),
                    new Uri("http://localhost:5001/signout-oidc")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                ApplicationType = ApplicationTypes.Web
            });
            logger.LogInformation("Web application OIDC client created successfully.");
        }
        
        // Create public SPA client (for JavaScript apps)
        if (await applicationManager.FindByClientIdAsync("mrwho-spa-client") == null)
        {
            logger.LogInformation("Creating SPA OIDC client...");
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mrwho-spa-client",
                DisplayName = "MrWho SPA Application",
                RedirectUris =
                {
                    new Uri("https://localhost:3000/callback"),
                    new Uri("http://localhost:3000/callback"),
                    new Uri("https://localhost:4200/callback"),
                    new Uri("http://localhost:4200/callback")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:3000/"),
                    new Uri("http://localhost:3000/"),
                    new Uri("https://localhost:4200/"),
                    new Uri("http://localhost:4200/")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles
                },
                ApplicationType = ApplicationTypes.Native
            });
            logger.LogInformation("SPA OIDC client created successfully.");
        }
        
        // Seed default admin user
        logger.LogInformation("Checking for default admin user...");
        if (await userManager.FindByEmailAsync("admin@mrwho.com") == null)
        {
            logger.LogInformation("Creating default admin user...");
            var adminUser = new ApplicationUser
            {
                UserName = "admin@mrwho.com",
                Email = "admin@mrwho.com",
                FirstName = "Admin",
                LastName = "User",
                EmailConfirmed = true,
                IsActive = true
            };
            
            var result = await userManager.CreateAsync(adminUser, "Admin123!");
            if (result.Succeeded)
            {
                logger.LogInformation("Default admin user created successfully.");
            }
            else
            {
                logger.LogError("Failed to create default admin user: {Errors}", 
                    string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            logger.LogInformation("Default admin user already exists, skipping creation.");
        }
        
        logger.LogInformation("Database initialization completed successfully.");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred during database initialization.");
        throw;
    }
}

app.Run();
