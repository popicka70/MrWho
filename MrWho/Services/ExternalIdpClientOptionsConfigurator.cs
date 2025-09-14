using System.Data.Common;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Options;
using MrWho.Data;
using OpenIddict.Client;

namespace MrWho.Services;

/// <summary>
/// Dynamically configures OpenIddict.Client registrations from the database IdentityProviders table at startup.
/// </summary>
public sealed class ExternalIdpClientOptionsConfigurator : IConfigureOptions<OpenIddictClientOptions>
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ExternalIdpClientOptionsConfigurator> _logger;

    public ExternalIdpClientOptionsConfigurator(IServiceScopeFactory scopeFactory, ILogger<ExternalIdpClientOptionsConfigurator> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public void Configure(OpenIddictClientOptions options)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            // If the database is not ready yet, skip dynamic registration to avoid startup failures.
            if (!CanUseIdentityProvidersTable(db))
            {
                _logger.LogInformation("Skipping external IdP registration: database or IdentityProviders table not ready yet");
                return;
            }

            var providers = db.IdentityProviders
                .AsNoTracking()
                .Where(p => p.IsEnabled && p.Type == MrWho.Shared.IdentityProviderType.Oidc)
                .OrderBy(p => p.Order)
                .ToList();

            foreach (var p in providers)
            {
                // Validate minimal configuration
                if (string.IsNullOrWhiteSpace(p.Authority))
                {
                    _logger.LogWarning("Skipping IdP {Name}: missing Authority", p.Name);
                    continue;
                }
                if (string.IsNullOrWhiteSpace(p.ClientId))
                {
                    _logger.LogWarning("Skipping IdP {Name}: missing ClientId", p.Name);
                    continue;
                }

                var registration = new OpenIddictClientRegistration
                {
                    ProviderName = p.Name,
                    Issuer = new System.Uri(p.Authority!, System.UriKind.Absolute),
                    ClientId = p.ClientId,
                    ClientSecret = p.ClientSecret
                };

                // Scopes: space-separated or JSON array
                foreach (var s in ParseScopes(p.Scopes))
                {
                    registration.Scopes.Add(s);
                }
                if (registration.Scopes.Count == 0)
                {
                    registration.Scopes.Add("openid");
                    registration.Scopes.Add("profile");
                    registration.Scopes.Add("email");
                }

                options.Registrations.Add(registration);
                _logger.LogInformation("Registered external OIDC provider {Name}", p.Name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to configure OpenIddict.Client registrations from database");
        }
    }

    private static bool CanUseIdentityProvidersTable(ApplicationDbContext db)
    {
        try
        {
            // Ensure we can connect
            if (!db.Database.CanConnect()) return false;

            // Use the context-managed connection but don't dispose it here
            var connection = db.Database.GetDbConnection();
            var shouldClose = false;
            if (connection.State != System.Data.ConnectionState.Open)
            {
                connection.Open();
                shouldClose = true;
            }

            try
            {
                using var cmd = connection.CreateCommand();
                cmd.CommandText = "select count(1) from information_schema.tables where table_schema = 'public' and lower(table_name) = 'identityproviders'";
                var result = cmd.ExecuteScalar();
                var count = Convert.ToInt32(result);
                return count > 0;
            }
            finally
            {
                if (shouldClose)
                {
                    connection.Close();
                }
            }
        }
        catch
        {
            // Any failure means the table isn't usable yet
            return false;
        }
    }

    private static IEnumerable<string> ParseScopes(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) yield break;
        raw = raw.Trim();
        if (raw.StartsWith("["))
        {
            string[]? arr = null;
            try
            {
                arr = JsonSerializer.Deserialize<string[]>(raw);
            }
            catch { }
            if (arr != null)
            {
                foreach (var s in arr)
                {
                    var v = s?.Trim();
                    if (!string.IsNullOrWhiteSpace(v)) yield return v;
                }
                yield break;
            }
        }
        foreach (var part in raw.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return part;
        }
    }
}
