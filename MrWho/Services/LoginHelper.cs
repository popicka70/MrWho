using System.Net.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace MrWho.Services;

public interface ILoginHelper
{
    bool ShouldUseRecaptcha();
    Task<bool> VerifyRecaptchaAsync(HttpContext http, string? token, string actionExpected);
    string? TryExtractClientIdFromReturnUrl(string? returnUrl);
    bool IsLocalUrl(string? url);
    string? GetRecaptchaSiteKey();
}

public sealed class LoginHelper : ILoginHelper
{
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHostEnvironment _env;

    public LoginHelper(IConfiguration configuration, IHttpClientFactory httpClientFactory, IHostEnvironment env)
    {
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
        _env = env;
    }

    public bool ShouldUseRecaptcha()
    {
        // Disable reCAPTCHA for automated test runs to avoid external HTTP dependency and token requirement
        var testFlag = Environment.GetEnvironmentVariable("MRWHO_TESTS");
        var envName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        if (string.Equals(testFlag, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(envName, "Testing", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (_env.IsDevelopment()) return false;
        var site = _configuration["GoogleReCaptcha:SiteKey"];
        var secret = _configuration["GoogleReCaptcha:SecretKey"];
        var enabledFlag = _configuration["GoogleReCaptcha:Enabled"];
        if (!string.IsNullOrWhiteSpace(enabledFlag) && bool.TryParse(enabledFlag, out var enabled) && !enabled)
            return false;
        return !string.IsNullOrWhiteSpace(site) && !string.IsNullOrWhiteSpace(secret);
    }

    public async Task<bool> VerifyRecaptchaAsync(HttpContext http, string? token, string actionExpected)
    {
        if (!ShouldUseRecaptcha()) return true;
        var secret = _configuration["GoogleReCaptcha:SecretKey"];
        if (string.IsNullOrWhiteSpace(token)) return false;
        var client = _httpClientFactory.CreateClient();
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["secret"] = secret!,
            ["response"] = token,
            ["remoteip"] = http.Connection.RemoteIpAddress?.ToString() ?? string.Empty
        });
        var resp = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
        if (!resp.IsSuccessStatusCode) return false;
        using var s = await resp.Content.ReadAsStreamAsync();
        var result = await System.Text.Json.JsonSerializer.DeserializeAsync<RecaptchaVerifyResult>(s, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (result == null || !result.success) return false;
        var threshold = 0.5;
        var cfgThr = _configuration["GoogleReCaptcha:Threshold"];
        if (double.TryParse(cfgThr, out var t)) threshold = t;
        if (!string.Equals(result.action, actionExpected, StringComparison.OrdinalIgnoreCase)) return false;
        return result.score >= threshold;
    }

    public string? TryExtractClientIdFromReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) return null;
        try
        {
            if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var absUri))
            {
                var query = System.Web.HttpUtility.ParseQueryString(absUri.Query);
                return query["client_id"];            
            }
            else
            {
                var idx = returnUrl.IndexOf('?');
                if (idx >= 0 && idx < returnUrl.Length - 1)
                {
                    var query = System.Web.HttpUtility.ParseQueryString(returnUrl.Substring(idx));
                    return query["client_id"];            
                }
            }
        }
        catch { }
        return null;
    }

    public bool IsLocalUrl(string? url) => !string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//") && !url.StartsWith("/\\");

    public string? GetRecaptchaSiteKey()
        => ShouldUseRecaptcha() ? _configuration["GoogleReCaptcha:SiteKey"] : null;

    private record RecaptchaVerifyResult(bool success, double score, string action, string hostname, DateTime challenge_ts, string[]? error_codes);
}
