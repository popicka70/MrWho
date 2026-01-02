using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MrWhoOidc.Client.DependencyInjection;
using MrWhoOidc.Client.Jwks;
using MrWhoOidc.Client.Options;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add MrWhoOidc Client services (Discovery, JWKS caching)
builder.Services.AddMrWhoOidcClient(builder.Configuration, "MrWhoOidc");

// Configure Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

builder.Services.AddAuthorization();

// Configure JWT Bearer options to use MrWhoOidc JWKS cache
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IServiceProvider>((options, sp) =>
    {
        var clientOptions = sp.GetRequiredService<IOptionsMonitor<MrWhoOidcClientOptions>>().CurrentValue;
        
        options.RequireHttpsMetadata = clientOptions.RequireHttpsMetadata;
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidIssuer = clientOptions.Issuer;
        
        // Validate audience
        var expectedAudience = clientOptions.Audience ?? clientOptions.Resource ?? "obo-demo-api";
        options.TokenValidationParameters.ValidateAudience = true;
        options.TokenValidationParameters.ValidAudience = expectedAudience;
        
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.RequireSignedTokens = true;
        
        // Use shared JWKS cache for key resolution
        options.TokenValidationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
        {
            var cache = sp.GetRequiredService<IMrWhoJwksCache>();
            var jwks = cache.GetAsync().AsTask().GetAwaiter().GetResult();
            IEnumerable<JsonWebKey> keys = jwks.Keys;
            if (!string.IsNullOrEmpty(kid))
            {
                keys = keys.Where(k => string.Equals(k.Kid, kid, StringComparison.Ordinal));
            }
            return keys.Cast<SecurityKey>();
        };
    });

builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");

// GET /me - Returns information about the token subject and actor
app.MapGet("/me", (ClaimsPrincipal user) =>
{
    // Extract subject claims
    var subject = user.FindFirst("sub")?.Value;
    var name = user.FindFirst("name")?.Value;
    var email = user.FindFirst("email")?.Value;
    
    // Extract actor claim (populated by OBO)
    var actClaim = user.FindFirst("act")?.Value;
    string? actorClientId = null;
    if (!string.IsNullOrEmpty(actClaim))
    {
        try 
        {
            // Parse {"sub": "dotnet-mvc-demo"} from act claim
            using var doc = JsonDocument.Parse(actClaim);
            if (doc.RootElement.TryGetProperty("sub", out var subProp))
            {
                actorClientId = subProp.GetString();
            }
        }
        catch
        {
            // Fallback if not JSON
            actorClientId = actClaim;
        }
    }
    
    return Results.Ok(new
    {
        message = "Called on behalf of user",
        subject,
        name,
        email,
        actor = actorClientId,
        audience = user.FindFirst("aud")?.Value,
        scopes = user.FindFirst("scope")?.Value?.Split(' ', StringSplitOptions.RemoveEmptyEntries),
        issuedAt = user.FindFirst("iat")?.Value,
        expiresAt = user.FindFirst("exp")?.Value
    });
}).RequireAuthorization();

app.Run();
