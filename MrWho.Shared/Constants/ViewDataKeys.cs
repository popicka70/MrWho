namespace MrWho.Shared.Constants;

/// <summary>
/// Centralized string constants for ViewData / TempData keys used across the MrWho solution.
/// Helps eliminate magic strings and reduces risk of typos.
/// </summary>
public static class ViewDataKeys
{
    public const string ReturnUrl = "ReturnUrl";
    public const string ClientId = "ClientId";
    public const string ClientName = "ClientName";
    public const string RecaptchaSiteKey = "RecaptchaSiteKey";
    public const string LogoUri = "LogoUri";
    public const string ThemeName = "ThemeName";
    public const string CustomCssUrl = "CustomCssUrl";
    public const string RegistrationSuccess = "RegistrationSuccess";
    public const string RequestedScopes = "RequestedScopes";
    public const string AlreadyGranted = "AlreadyGranted";
    public const string MissingScopes = "MissingScopes";
    public const string LogoutError = "LogoutError";

    // Login option flags
    public const string AllowLocalLogin = "AllowLocalLogin";
    public const string AllowPasskeyLogin = "AllowPasskeyLogin";
    public const string AllowQrLoginQuick = "AllowQrLoginQuick";
    public const string AllowQrLoginSecure = "AllowQrLoginSecure";
    public const string AllowCodeLogin = "AllowCodeLogin";

    // External identity providers collection
    public const string ExternalProviders = "ExternalProviders";
}
