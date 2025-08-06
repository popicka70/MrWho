namespace MrWho.Shared;

/// <summary>
/// Constants for token property names and OAuth2/OIDC parameters
/// </summary>
public static class TokenConstants
{
    /// <summary>
    /// Token property names used with GetTokenAsync/UpdateTokenValue
    /// </summary>
    public static class TokenNames
    {
        public const string AccessToken = "access_token";
        public const string RefreshToken = "refresh_token";
        public const string IdToken = "id_token";
        public const string ExpiresAt = "expires_at";
        public const string TokenType = "token_type";
    }

    /// <summary>
    /// OAuth2/OIDC parameter names for token requests
    /// </summary>
    public static class ParameterNames
    {
        public const string GrantType = "grant_type";
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string RefreshToken = "refresh_token";
        public const string Username = "username";
        public const string Password = "password";
        public const string Scope = "scope";
        public const string Code = "code";
        public const string RedirectUri = "redirect_uri";
        public const string CodeVerifier = "code_verifier";
        public const string CodeChallenge = "code_challenge";
        public const string CodeChallengeMethod = "code_challenge_method";
        public const string State = "state";
        public const string Nonce = "nonce";
        public const string ResponseType = "response_type";
        public const string ResponseMode = "response_mode";
    }

    /// <summary>
    /// OAuth2 grant type values
    /// </summary>
    public static class GrantTypes
    {
        public const string AuthorizationCode = "authorization_code";
        public const string ClientCredentials = "client_credentials";
        public const string Password = "password";
        public const string RefreshToken = "refresh_token";
        public const string Implicit = "implicit";
        public const string DeviceCode = "device_code";
    }

    /// <summary>
    /// OAuth2 response type values
    /// </summary>
    public static class ResponseTypes
    {
        public const string Code = "code";
        public const string Token = "token";
        public const string IdToken = "id_token";
        public const string CodeToken = "code token";
        public const string CodeIdToken = "code id_token";
        public const string TokenIdToken = "token id_token";
        public const string CodeTokenIdToken = "code token id_token";
    }

    /// <summary>
    /// JSON property names for token responses
    /// </summary>
    public static class JsonPropertyNames
    {
        public const string AccessToken = "access_token";
        public const string RefreshToken = "refresh_token";
        public const string IdToken = "id_token";
        public const string TokenType = "token_type";
        public const string ExpiresIn = "expires_in";
        public const string Scope = "scope";
        public const string Error = "error";
        public const string ErrorDescription = "error_description";
        public const string ErrorUri = "error_uri";
    }

    /// <summary>
    /// Common token type values
    /// </summary>
    public static class TokenTypes
    {
        public const string Bearer = "Bearer";
        public const string Mac = "mac";
        public const string Pop = "pop";
    }

    /// <summary>
    /// PKCE code challenge method values
    /// </summary>
    public static class CodeChallengeMethods
    {
        public const string Plain = "plain";
        public const string S256 = "S256";
    }

    /// <summary>
    /// Common OAuth2 error codes
    /// </summary>
    public static class ErrorCodes
    {
        public const string InvalidRequest = "invalid_request";
        public const string InvalidClient = "invalid_client";
        public const string InvalidGrant = "invalid_grant";
        public const string UnauthorizedClient = "unauthorized_client";
        public const string UnsupportedGrantType = "unsupported_grant_type";
        public const string InvalidScope = "invalid_scope";
        public const string AccessDenied = "access_denied";
        public const string UnsupportedResponseType = "unsupported_response_type";
        public const string ServerError = "server_error";
        public const string TemporarilyUnavailable = "temporarily_unavailable";
    }
}