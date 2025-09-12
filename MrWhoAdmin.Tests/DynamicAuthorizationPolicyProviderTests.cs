using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using MrWho.Models;
using MrWho.Services;
using MrWho.Shared;

namespace MrWhoAdmin.Tests;

[TestClass]
public class DynamicAuthorizationPolicyProviderTests
{
    private sealed class TestCookieOptionsMonitor : IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>
    {
        private readonly Dictionary<string, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions> _map;
        public TestCookieOptionsMonitor(Dictionary<string, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions> map) => _map = map;
        public Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions CurrentValue => Get("default");
        public Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions Get(string? name)
            => _map.TryGetValue(name ?? string.Empty, out var o) ? o : new Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions { Cookie = { Name = (name ?? "default") + "+cookie" } };
        public IDisposable OnChange(Action<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions, string> listener) => new Dummy();
        private sealed class Dummy : IDisposable { public void Dispose() { } }
    }

    private sealed class TestSchemeProvider : IAuthenticationSchemeProvider
    {
        private readonly HashSet<string> _schemes;
        public TestSchemeProvider(IEnumerable<string> schemes) => _schemes = schemes.ToHashSet();
        public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() => Task.FromResult(_schemes.Select(s => new AuthenticationScheme(s, s, typeof(TestHandler))) as IEnumerable<AuthenticationScheme>);
        public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() => GetAllSchemesAsync();
        public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
        public Task<AuthenticationScheme?> GetSchemeAsync(string name) => Task.FromResult(_schemes.Contains(name) ? new AuthenticationScheme(name, name, typeof(TestHandler)) : null);
        public void AddScheme(AuthenticationScheme scheme) => _schemes.Add(scheme.Name);
        public void RemoveScheme(string name) => _schemes.Remove(name);
        private sealed class TestHandler : IAuthenticationHandler
        {
            public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context) => Task.CompletedTask;
            public Task<AuthenticateResult> AuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
            public Task ChallengeAsync(AuthenticationProperties? properties) => Task.CompletedTask;
            public Task ForbidAsync(AuthenticationProperties? properties) => Task.CompletedTask;
        }
    }

    private DynamicAuthorizationPolicyProvider CreateProvider(out ServiceProvider sp, IEnumerable<Client>? enabledClients = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.Configure<AuthorizationOptions>(_ => { });

        var clients = enabledClients?.ToList() ?? new List<Client>
        {
            new Client { ClientId = "c1", Name = "C1", IsEnabled = true, Realm = new Realm { Name = "r", DisplayName = "R", IsEnabled = true }, RealmId = Guid.NewGuid().ToString() },
            new Client { ClientId = "c2", Name = "C2", IsEnabled = true, Realm = new Realm { Name = "r", DisplayName = "R", IsEnabled = true }, RealmId = Guid.NewGuid().ToString() }
        };

        var oidcSvc = new Mock<IOidcClientService>();
        oidcSvc.Setup(s => s.GetEnabledClientsAsync()).ReturnsAsync(clients);
        services.AddSingleton(oidcSvc.Object);

        var cookieOptions = new TestCookieOptionsMonitor(new Dictionary<string, Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>
        {
            ["Identity.Application.c1"] = new() { Cookie = { Name = "c1cookie" } },
            ["Identity.Application.c2"] = new() { Cookie = { Name = "c2cookie" } }
        });
        services.AddSingleton<IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>(cookieOptions);

        var schemes = new[] { "Identity.Application", "Identity.Application.c1", "Identity.Application.c2", OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme };
        services.AddSingleton<IAuthenticationSchemeProvider>(new TestSchemeProvider(schemes));

        sp = services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptions<AuthorizationOptions>>();
        return new DynamicAuthorizationPolicyProvider(options, sp.GetRequiredService<IServiceScopeFactory>(), sp.GetRequiredService<ILogger<DynamicAuthorizationPolicyProvider>>());
    }

    [TestMethod]
    public async Task DefaultPolicy_Includes_Dynamic_Client_Schemes()
    {
        var provider = CreateProvider(out var sp);
        var policy = await provider.GetDefaultPolicyAsync();
        Assert.IsTrue(policy.AuthenticationSchemes.Contains("Identity.Application.c1"));
        Assert.IsTrue(policy.AuthenticationSchemes.Contains("Identity.Application.c2"));
    }

    [TestMethod]
    public async Task ClientPolicy_Builds_For_ClientPrefix()
    {
        var provider = CreateProvider(out _);
        var policy = await provider.GetPolicyAsync("Client_c1");
        Assert.IsNotNull(policy);
        Assert.AreEqual(1, policy!.AuthenticationSchemes.Count(s => s == "Identity.Application.c1"));
    }

    [TestMethod]
    public async Task AdminClientApiPolicy_Allows_Admin_Client_With_Scope()
    {
        var provider = CreateProvider(out var sp, Array.Empty<Client>());
        var policy = await provider.GetPolicyAsync(AuthorizationPolicies.AdminClientApi);
        Assert.IsNotNull(policy);
        var claims = new List<Claim>
        {
            new("client_id", MrWhoConstants.AdminClientId),
            new("scope", StandardScopes.MrWhoUse)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAuthorizationPolicyProvider>(provider);
        services.AddAuthorization();
        foreach (var svc in sp.GetServices<IAuthenticationSchemeProvider>()) services.AddSingleton(svc);
        var authSp = services.BuildServiceProvider();
        var authz = authSp.GetRequiredService<IAuthorizationService>();
        var result = await authz.AuthorizeAsync(principal, null, policy!);
        Assert.IsTrue(result.Succeeded, "Authorization should succeed for admin client with scope");
    }
}
