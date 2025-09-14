using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using MrWho.ClientAuth.Jar;

namespace MrWho.ClientAuth.Par;

internal sealed class PushedAuthorizationService : IPushedAuthorizationService
{
    private readonly HttpClient _http;
    private readonly ParClientOptions _options;
    private readonly IJarRequestObjectSigner? _jarSigner;

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public PushedAuthorizationService(HttpClient http, ParClientOptions options, IServiceProvider services)
    {
        _http = http; _options = options;
        _http.Timeout = options.Timeout;
        _jarSigner = services.GetService(typeof(IJarRequestObjectSigner)) as IJarRequestObjectSigner;
    }

    private static string GenerateNonce(int bytes = 16)
    {
        var data = RandomNumberGenerator.GetBytes(bytes);
        var b64 = Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return b64;
    }

    public async Task<(ParResult? Result, ParError? Error)> PushAsync(AuthorizationRequest request, CancellationToken ct = default)
    {
        // Ensure nonce exists (OIDC best practice) prior to JAR/PAR
        if (string.IsNullOrWhiteSpace(request.Nonce)) {
            request.Nonce = GenerateNonce();
        }

        // Auto-create JAR if requested and not already set
        if (_options.AutoJar && _jarSigner != null && string.IsNullOrEmpty(request.RequestObjectJwt))
        {
            var jarReq = new JarRequest
            {
                ClientId = request.ClientId,
                RedirectUri = request.RedirectUri,
                Scope = request.Scope,
                ResponseType = request.ResponseType,
                State = request.State,
                CodeChallenge = request.CodeChallenge,
                CodeChallengeMethod = request.CodeChallengeMethod ?? "S256",
                Nonce = request.Nonce
            };
            foreach (var kv in request.Extra) {
                jarReq.Extra[kv.Key] = kv.Value;
            }

            request.RequestObjectJwt = await _jarSigner.CreateRequestObjectAsync(jarReq, ct);
        }

        // Determine Basic vs body secret
        string? secretForBasic = null;
        if (!string.IsNullOrWhiteSpace(request.ClientSecret) && request.UseBasicAuth)
        {
            secretForBasic = request.ClientSecret;
        }
        else if (request.Extra.TryGetValue("client_secret_for_par_auth", out var tmpSecret) && !string.IsNullOrWhiteSpace(tmpSecret))
        {
            secretForBasic = tmpSecret; // legacy support
        }

        var form = new List<KeyValuePair<string?, string?>>
        {
            new("client_id", request.ClientId),
            new("redirect_uri", request.RedirectUri),
            new("response_type", request.ResponseType)
        };
        if (!string.IsNullOrWhiteSpace(request.Scope)) {
            form.Add(new("scope", request.Scope));
        }

        if (!string.IsNullOrWhiteSpace(request.State)) {
            form.Add(new("state", request.State));
        }

        if (!string.IsNullOrWhiteSpace(request.Nonce)) {
            form.Add(new("nonce", request.Nonce)); // add nonce to PAR payload
        }

        if (!string.IsNullOrWhiteSpace(request.CodeChallenge))
        {
            form.Add(new("code_challenge", request.CodeChallenge));
            form.Add(new("code_challenge_method", request.CodeChallengeMethod ?? "S256"));
        }
        if (!string.IsNullOrWhiteSpace(request.RequestObjectJwt)) {
            form.Add(new("request", request.RequestObjectJwt));
        }

        foreach (var kv in request.Extra)
        {
            if (kv.Key is "client_secret_for_par_auth" or "client_secret") {
                continue;
            }

            form.Add(new(kv.Key, kv.Value));
        }
        // Optional inline secret (if caller prefers body instead of Basic)
        if (secretForBasic == null && !string.IsNullOrWhiteSpace(request.ClientSecret) && !request.UseBasicAuth)
        {
            form.Add(new("client_secret", request.ClientSecret));
        }

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, _options.ParEndpoint)
        {
            Content = new FormUrlEncodedContent(form)
        };
        if (secretForBasic != null)
        {
            var raw = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{request.ClientId}:{secretForBasic}"));
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Basic", raw);
        }

        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(httpRequest, ct); }
        catch (Exception ex)
        {
            return (null, new ParError { Error = "network_error", ErrorDescription = ex.Message, StatusCode = 0 });
        }

        var body = await resp.Content.ReadAsStringAsync(ct);
        if (resp.IsSuccessStatusCode)
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                var requestUri = root.GetProperty("request_uri").GetString();
                var expiresIn = root.GetProperty("expires_in").GetInt32();
                if (string.IsNullOrWhiteSpace(requestUri)) {
                    throw new InvalidOperationException("Missing request_uri");
                }

                return (new ParResult { RequestUri = requestUri!, ExpiresIn = expiresIn }, null);
            }
            catch (Exception ex)
            {
                return (null, new ParError { Error = "parse_error", ErrorDescription = ex.Message, StatusCode = (int)resp.StatusCode });
            }
        }
        else
        {
            (ParResult? Result, ParError? Error) emptyErr = (null, new ParError { Error = "http_" + (int)resp.StatusCode, ErrorDescription = body, StatusCode = (int)resp.StatusCode });
            try
            {
                if (string.IsNullOrWhiteSpace(body))
                {
                    return emptyErr;
                }
                else
                {
                    using var doc = JsonDocument.Parse(body);
                    var root = doc.RootElement;
                    var err = root.TryGetProperty("error", out var errEl) ? errEl.GetString() ?? "invalid_request" : "invalid_request";
                    var desc = root.TryGetProperty("error_description", out var dEl) ? dEl.GetString() : null;
                    return (null, new ParError { Error = err, ErrorDescription = desc, StatusCode = (int)resp.StatusCode });
                }
            }
            catch
            {
                return emptyErr;
            }
        }
    }

    public async Task<Uri> BuildAuthorizeUrlAsync(AuthorizationRequest request, CancellationToken ct = default)
    {
        // Ensure nonce pre-populated for front-channel fallback
        if (string.IsNullOrWhiteSpace(request.Nonce)) {
            request.Nonce = GenerateNonce();
        }

        var authorizeEndpoint = _options.AuthorizeEndpoint ?? new Uri(_options.ParEndpoint.GetLeftPart(UriPartial.Authority) + "/connect/authorize");
        if (request.Extra.TryGetValue("request_uri", out var existing))
        {
            var qb = HttpUtility.ParseQueryString(string.Empty);
            qb["client_id"] = request.ClientId;
            qb["request_uri"] = existing;
            return new Uri(authorizeEndpoint + "?" + qb.ToString());
        }
        var directQuery = BuildDirectQuery(request);
        bool mustPush = _options.AutoPushQueryLengthThreshold > 0 && directQuery.Length > _options.AutoPushQueryLengthThreshold;
        if (request.Extra.TryGetValue("use_par", out var flag) && (flag == "1" || flag.Equals("true", StringComparison.OrdinalIgnoreCase))) {
            mustPush = true;
        }

        if (!mustPush && _options.AutoJar && _jarSigner != null && string.IsNullOrEmpty(request.RequestObjectJwt))
        {
            if (request.Extra.TryGetValue("auto_jar", out var v) && (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase))) {
                mustPush = true;
            }
        }
        if (mustPush)
        {
            var (result, error) = await PushAsync(request, ct);
            if (result != null)
            {
                var qb = HttpUtility.ParseQueryString(string.Empty);
                qb["client_id"] = request.ClientId;
                qb["request_uri"] = result.RequestUri;
                return new Uri(authorizeEndpoint + "?" + qb.ToString());
            }
            if (error != null && _options.FallbackWhenDisabled && string.Equals(error.Error, "invalid_request", StringComparison.OrdinalIgnoreCase) && (error.ErrorDescription?.Contains("PAR disabled", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                return new Uri(authorizeEndpoint + "?" + directQuery);
            }
            throw new InvalidOperationException($"PAR push failed: {error?.Error} {error?.ErrorDescription}");
        }
        if (_options.AutoJar && _jarSigner != null && string.IsNullOrEmpty(request.RequestObjectJwt))
        {
            var jarReq = new JarRequest
            {
                ClientId = request.ClientId,
                RedirectUri = request.RedirectUri,
                Scope = request.Scope,
                ResponseType = request.ResponseType,
                State = request.State,
                CodeChallenge = request.CodeChallenge,
                CodeChallengeMethod = request.CodeChallengeMethod ?? "S256",
                Nonce = request.Nonce
            };
            foreach (var kv in request.Extra) {
                jarReq.Extra[kv.Key] = kv.Value;
            }

            request.RequestObjectJwt = await _jarSigner.CreateRequestObjectAsync(jarReq, ct);
            directQuery = BuildDirectQuery(request);
        }
        return new Uri(authorizeEndpoint + "?" + directQuery);
    }

    private static string BuildDirectQuery(AuthorizationRequest req)
    {
        var qb = HttpUtility.ParseQueryString(string.Empty);
        qb["client_id"] = req.ClientId;
        qb["redirect_uri"] = req.RedirectUri;
        qb["response_type"] = req.ResponseType;
        if (!string.IsNullOrWhiteSpace(req.Scope)) {
            qb["scope"] = req.Scope;
        }

        if (!string.IsNullOrWhiteSpace(req.State)) {
            qb["state"] = req.State;
        }

        if (!string.IsNullOrWhiteSpace(req.Nonce)) {
            qb["nonce"] = req.Nonce; // ensure nonce appears in direct authorization URL
        }

        if (!string.IsNullOrWhiteSpace(req.CodeChallenge))
        {
            qb["code_challenge"] = req.CodeChallenge;
            qb["code_challenge_method"] = req.CodeChallengeMethod ?? "S256";
        }
        if (!string.IsNullOrWhiteSpace(req.RequestObjectJwt)) {
            qb["request"] = req.RequestObjectJwt;
        }

        foreach (var kv in req.Extra)
        {
            if (qb[kv.Key] != null) {
                continue;
            }

            qb[kv.Key] = kv.Value;
        }
        return qb.ToString();
    }
}
