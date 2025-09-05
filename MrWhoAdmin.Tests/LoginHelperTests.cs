using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.FileProviders;
using Moq;
using MrWho.Services;

namespace MrWhoAdmin.Tests;

[TestClass]
public class LoginHelperTests
{
    private static LoginHelper CreateHelper(IDictionary<string,string?>? settings = null, string environmentName = "Development")
    {
        var dict = settings ?? new Dictionary<string,string?>();
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict!).Build();
        var httpClientFactory = new Mock<IHttpClientFactory>();
        var envMock = new Mock<IHostEnvironment>();
        envMock.SetupGet(e => e.EnvironmentName).Returns(environmentName);
        envMock.SetupGet(e => e.ApplicationName).Returns("TestApp");
        envMock.SetupGet(e => e.ContentRootPath).Returns(AppContext.BaseDirectory);
        envMock.SetupGet(e => e.ContentRootFileProvider).Returns(new NullFileProvider());
        return new LoginHelper(config, httpClientFactory.Object, envMock.Object);
    }

    [TestMethod]
    public void ShouldUseRecaptcha_ReturnsFalse_InDevelopment()
    {
        var helper = CreateHelper(new Dictionary<string,string?>
        {
            ["GoogleReCaptcha:SiteKey"] = "site",
            ["GoogleReCaptcha:SecretKey"] = "secret"
        }, environmentName: "Development");

        helper.ShouldUseRecaptcha().Should().BeFalse();
    }

    [TestMethod]
    public void ShouldUseRecaptcha_ReturnsTrue_WhenConfiguredInProduction()
    {
        var originalTests = Environment.GetEnvironmentVariable("MRWHO_TESTS");
        var originalEnv = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        try
        {
            Environment.SetEnvironmentVariable("MRWHO_TESTS", null);
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
            var helper = CreateHelper(new Dictionary<string,string?>
            {
                ["GoogleReCaptcha:SiteKey"] = "site",
                ["GoogleReCaptcha:SecretKey"] = "secret"
            }, environmentName: "Production");
            helper.ShouldUseRecaptcha().Should().BeTrue();
        }
        finally
        {
            Environment.SetEnvironmentVariable("MRWHO_TESTS", originalTests);
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", originalEnv);
        }
    }

    [TestMethod]
    public async Task VerifyRecaptchaAsync_ShortCircuits_WhenDisabled()
    {
        var helper = CreateHelper(new Dictionary<string,string?>(), environmentName: "Development");
        var ctx = new DefaultHttpContext();
        var result = await helper.VerifyRecaptchaAsync(ctx, token: null, actionExpected: "login");
        result.Should().BeTrue("recaptcha disabled should always return true");
    }

    [TestMethod]
    public async Task VerifyRecaptchaAsync_ReturnsFalse_WhenEnabled_ButMissingToken()
    {
        var originalTests = Environment.GetEnvironmentVariable("MRWHO_TESTS");
        var originalEnv = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        try
        {
            Environment.SetEnvironmentVariable("MRWHO_TESTS", null);
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
            var helper = CreateHelper(new Dictionary<string,string?>
            {
                ["GoogleReCaptcha:SiteKey"] = "site",
                ["GoogleReCaptcha:SecretKey"] = "secret"
            }, environmentName: "Production");
            var ctx = new DefaultHttpContext();
            var ok = await helper.VerifyRecaptchaAsync(ctx, token: null, actionExpected: "login");
            ok.Should().BeFalse();
        }
        finally
        {
            Environment.SetEnvironmentVariable("MRWHO_TESTS", originalTests);
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", originalEnv);
        }
    }

    [DataTestMethod]
    [DataRow("/home", true)]
    [DataRow("//evil", false)]
    [DataRow("/\\hack", false)]
    [DataRow("http://external", false)]
    public void IsLocalUrl_Works(string url, bool expected)
    {
        var helper = CreateHelper();
        helper.IsLocalUrl(url).Should().Be(expected);
    }

    [TestMethod]
    public void TryExtractClientIdFromReturnUrl_Works_ForAbsolute()
    {
        var helper = CreateHelper();
        var cid = helper.TryExtractClientIdFromReturnUrl("https://server/connect/authorize?client_id=abc123&scope=openid");
        cid.Should().Be("abc123");
    }

    [TestMethod]
    public void TryExtractClientIdFromReturnUrl_Works_ForRelative()
    {
        var helper = CreateHelper();
        var cid = helper.TryExtractClientIdFromReturnUrl("/connect/authorize?client_id=xyz&scope=openid");
        cid.Should().Be("xyz");
    }

    [TestMethod]
    public void GetRecaptchaSiteKey_Null_WhenDisabled()
    {
        var helper = CreateHelper();
        helper.GetRecaptchaSiteKey().Should().BeNull();
    }
}
