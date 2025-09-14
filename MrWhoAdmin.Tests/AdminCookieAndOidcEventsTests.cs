using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace MrWhoAdmin.Tests;

[TestClass]
public class AdminCookieAndOidcEventsTests
{
    private (OpenIdConnectEvents OidcEvents, ServiceProvider Sp) Create()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var sp = services.BuildServiceProvider();

        var oidcEvents = new OpenIdConnectEvents
        {
            OnUserInformationReceived = ctx =>
            {
                if (ctx.Principal?.Identity is ClaimsIdentity identity)
                {
                    var root = ctx.User.RootElement;
                    var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        "sub","name","given_name","family_name","email","email_verified","preferred_username","phone_number","phone_number_verified","role","roles"
                    };
                    foreach (var prop in root.EnumerateObject())
                    {
                        if (known.Contains(prop.Name))
                        {
                            continue;
                        }

                        if (prop.Value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
                        {
                            continue;
                        }

                        bool Already(string type, string val) => identity.HasClaim(c => c.Type == type && c.Value == val);
                        void Add(string type, string val)
                        {
                            if (!string.IsNullOrWhiteSpace(val) && !Already(type, val))
                            {
                                identity.AddClaim(new Claim(type, val));
                            }
                        }
                        switch (prop.Value.ValueKind)
                        {
                            case JsonValueKind.String:
                                Add(prop.Name, prop.Value.GetString()!); break;
                            case JsonValueKind.True or JsonValueKind.False:
                                Add(prop.Name, prop.Value.GetBoolean().ToString()); break;
                            case JsonValueKind.Number:
                                if (prop.Value.TryGetInt64(out var l))
                                {
                                    Add(prop.Name, l.ToString());
                                }
                                else if (prop.Value.TryGetDouble(out var d))
                                {
                                    Add(prop.Name, d.ToString(CultureInfo.InvariantCulture));
                                }

                                break;
                            case JsonValueKind.Array:
                                foreach (var e in prop.Value.EnumerateArray())
                                {
                                    if (e.ValueKind == JsonValueKind.String)
                                    {
                                        Add(prop.Name, e.GetString()!);
                                    }
                                    else if (e.ValueKind is JsonValueKind.True or JsonValueKind.False)
                                    {
                                        Add(prop.Name, e.GetBoolean().ToString());
                                    }
                                }
                                break;
                            case JsonValueKind.Object:
                                try { Add(prop.Name, prop.Value.GetRawText()); } catch { }
                                break;
                        }
                    }
                }
                return Task.CompletedTask;
            }
        };

        return (oidcEvents, sp);
    }

    [TestMethod]
    public async Task Oidc_OnUserInformationReceived_Projects_All_Supported_ValueKinds_And_Suppresses_Duplicates()
    {
        var (oidcEvents, sp) = Create();
        var identity = new ClaimsIdentity(new[] { new Claim("sub", "abc") }, "oidc");
        var principal = new ClaimsPrincipal(identity);
        var json = "{\n  \"stringClaim\": \"value1\",\n  \"boolClaim\": true,\n  \"numClaim\": 123,\n  \"arrayClaim\": [\"a\", \"b\", true],\n  \"objClaim\": { \"nested\": 42 },\n  \"stringClaim\": \"value1\"\n}"; // duplicate stringClaim intentionally
        using var userInfoDoc = JsonDocument.Parse(json);
        var httpContext = new DefaultHttpContext { RequestServices = sp };
        var options = new OpenIdConnectOptions();
        var evtCtx = new UserInformationReceivedContext(httpContext, new AuthenticationScheme("oidc", "oidc", typeof(OpenIdConnectHandler)), options, principal, new AuthenticationProperties())
        { User = userInfoDoc };
        await oidcEvents.OnUserInformationReceived!(evtCtx);
        string? Find(string type) => identity.Claims.FirstOrDefault(c => c.Type == type)?.Value;
        Assert.AreEqual("value1", Find("stringClaim"));
        Assert.AreEqual("True", Find("boolClaim"));
        Assert.AreEqual("123", Find("numClaim"));
        var arrayValues = identity.Claims.Where(c => c.Type == "arrayClaim").Select(c => c.Value).OrderBy(v => v).ToList();
        CollectionAssert.AreEquivalent(new[] { "True", "a", "b" }, arrayValues);
        Assert.IsTrue(Find("objClaim")!.Contains("nested"));
        Assert.AreEqual(1, identity.Claims.Count(c => c.Type == "stringClaim"));
    }
}
