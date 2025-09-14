using Microsoft.AspNetCore.Components;
using MrWho.Shared; // added for enums
using MrWho.Shared.Models;
using MrWhoAdmin.Web.Services;
using Radzen;

namespace MrWhoAdmin.Web.Components.Pages;

public partial class EditRealmDefaults
{
    [Parameter] public string? Id { get; set; }

    [Inject] protected IRealmsApiService RealmsApiService { get; set; } = default!;
    [Inject] protected NavigationManager Navigation { get; set; } = default!;
    [Inject] protected NotificationService NotificationService { get; set; } = default!;
    [Inject] protected DialogService DialogService { get; set; } = default!;
    [Inject] protected ILogger<EditRealmDefaults> Logger { get; set; } = default!;

    internal UpdateRealmDefaultsRequest model = new();
    internal bool isLoading;
    internal int selectedTabIndex;
    internal string? realmDisplayName; // holds realm name for UI

    // Numeric wrappers for TimeSpan lifetimes
    internal int accessTokenMinutes
    {
        get => (int)Math.Round((model.AccessTokenLifetime == default ? MrWho.Shared.MrWhoConstants.TokenLifetimes.AccessToken : model.AccessTokenLifetime).TotalMinutes);
        set => model.AccessTokenLifetime = TimeSpan.FromMinutes(value);
    }
    internal int refreshTokenDays
    {
        get => (int)Math.Max(1, Math.Round((model.RefreshTokenLifetime == default ? MrWho.Shared.MrWhoConstants.TokenLifetimes.RefreshToken : model.RefreshTokenLifetime).TotalDays));
        set => model.RefreshTokenLifetime = TimeSpan.FromDays(value);
    }
    internal int authorizationCodeMinutes
    {
        get => (int)Math.Round((model.AuthorizationCodeLifetime == default ? MrWho.Shared.MrWhoConstants.TokenLifetimes.AuthorizationCode : model.AuthorizationCodeLifetime).TotalMinutes);
        set => model.AuthorizationCodeLifetime = TimeSpan.FromMinutes(value);
    }
    internal int idTokenMinutes
    {
        get => (int)Math.Round((model.IdTokenLifetime == default ? TimeSpan.FromMinutes(60) : model.IdTokenLifetime).TotalMinutes);
        set => model.IdTokenLifetime = TimeSpan.FromMinutes(value);
    }
    internal int deviceCodeMinutes
    {
        get => (int)Math.Round((model.DeviceCodeLifetime == default ? TimeSpan.FromMinutes(10) : model.DeviceCodeLifetime).TotalMinutes);
        set => model.DeviceCodeLifetime = TimeSpan.FromMinutes(value);
    }

    internal List<DropdownItem<string>> sameSitePolicies = new();
    internal List<DropdownItem<string>> availableMfaMethods = new();
    internal List<DropdownItem<string>> availableThemes = new()
    {
        new("Light", "light"),
        new("Dark", "dark"),
        new("Ocean", "ocean"),
        new("Forest", "forest"),
        new("Corporate", "corporate"),
        new("Sunset", "sunset"),
        new("Purple", "purple")
    };

    protected override async Task OnInitializedAsync()
    {
        InitializeDropdownData();
        await LoadRealmDefaults();
    }

    private void InitializeDropdownData()
    {
        sameSitePolicies = new()
        {
            new("None (Cross-site requests allowed)", "None"),
            new("Lax (Some cross-site requests)", "Lax"),
            new("Strict (No cross-site requests)", "Strict")
        };

        availableMfaMethods = new()
        {
            new("Time-based OTP (TOTP)", "totp"),
            new("SMS Verification", "sms"),
            new("Email Verification", "email"),
            new("Push Notifications", "push"),
            new("Hardware Token", "hardware"),
            new("Biometric", "biometric")
        };
    }

    // Added: maintain JAR alg multi-select state after load
    private void SyncJarAlgSelections()
    {
        // handled in .razor partial (OnParametersSet) when model changes
        StateHasChanged();
    }

    private async Task LoadRealmDefaults()
    {
        isLoading = true;
        try
        {
            var realm = await RealmsApiService.GetRealmAsync(Id!);
            if (realm != null)
            {
                model = MapRealmToDefaultsRequest(realm);
                realmDisplayName = !string.IsNullOrWhiteSpace(realm.DisplayName) && !string.Equals(realm.DisplayName, realm.Name, StringComparison.OrdinalIgnoreCase)
                    ? $"{realm.DisplayName} ({realm.Name})"
                    : realm.Name;
                SyncJarAlgSelections();
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error loading realm defaults {RealmId}", Id);
            NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to load realm defaults");
        }
        finally { isLoading = false; }
    }

    private static UpdateRealmDefaultsRequest MapRealmToDefaultsRequest(RealmDto realm) => new()
    {
        // Token lifetime defaults
        AccessTokenLifetime = realm.AccessTokenLifetime,
        RefreshTokenLifetime = realm.RefreshTokenLifetime,
        AuthorizationCodeLifetime = realm.AuthorizationCodeLifetime,
        IdTokenLifetime = realm.IdTokenLifetime,
        DeviceCodeLifetime = realm.DeviceCodeLifetime,

        // Session & cookies
        DefaultSessionTimeoutHours = realm.DefaultSessionTimeoutHours,
        DefaultRememberMeDurationDays = realm.DefaultRememberMeDurationDays,
        DefaultUseSlidingSessionExpiration = realm.DefaultUseSlidingSessionExpiration,
        DefaultCookieSameSitePolicy = realm.DefaultCookieSameSitePolicy,
        DefaultRequireHttpsForCookies = realm.DefaultRequireHttpsForCookies,

        // Security & compliance
        DefaultRequireConsent = realm.DefaultRequireConsent,
        DefaultAllowRememberConsent = realm.DefaultAllowRememberConsent,
        DefaultMaxRefreshTokensPerUser = realm.DefaultMaxRefreshTokensPerUser,
        DefaultUseOneTimeRefreshTokens = realm.DefaultUseOneTimeRefreshTokens,
        DefaultIncludeJwtId = realm.DefaultIncludeJwtId,

        // MFA
        DefaultRequireMfa = realm.DefaultRequireMfa,
        DefaultMfaGracePeriodMinutes = realm.DefaultMfaGracePeriodMinutes,
        DefaultAllowedMfaMethods = realm.DefaultAllowedMfaMethods,
        DefaultRememberMfaForSession = realm.DefaultRememberMfaForSession,

        // Rate limiting
        DefaultRateLimitRequestsPerMinute = realm.DefaultRateLimitRequestsPerMinute,
        DefaultRateLimitRequestsPerHour = realm.DefaultRateLimitRequestsPerHour,
        DefaultRateLimitRequestsPerDay = realm.DefaultRateLimitRequestsPerDay,

        // Logging
        DefaultEnableDetailedErrors = realm.DefaultEnableDetailedErrors,
        DefaultLogSensitiveData = realm.DefaultLogSensitiveData,

        // Branding
        DefaultThemeName = realm.DefaultThemeName,
        RealmCustomCssUrl = realm.RealmCustomCssUrl,
        RealmLogoUri = realm.RealmLogoUri,
        RealmUri = realm.RealmUri,
        RealmPolicyUri = realm.RealmPolicyUri,
        RealmTosUri = realm.RealmTosUri,

        // NEW: JAR/JARM defaults
        DefaultJarMode = realm.DefaultJarMode,
        DefaultJarmMode = realm.DefaultJarmMode,
        DefaultRequireSignedRequestObject = realm.DefaultRequireSignedRequestObject,
        DefaultAllowedRequestObjectAlgs = realm.DefaultAllowedRequestObjectAlgs
    };

    internal bool IsMethodSelected(string method)
    {
        if (string.IsNullOrWhiteSpace(model.DefaultAllowedMfaMethods)) return false;
        try
        {
            var methods = System.Text.Json.JsonSerializer.Deserialize<string[]>(model.DefaultAllowedMfaMethods);
            return methods?.Contains(method) == true;
        }
        catch { return false; }
    }

    internal void ToggleMfaMethod(string method, bool selected)
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(model.DefaultAllowedMfaMethods))
        {
            try
            {
                var existing = System.Text.Json.JsonSerializer.Deserialize<string[]>(model.DefaultAllowedMfaMethods);
                if (existing != null) list.AddRange(existing);
            }
            catch { }
        }
        if (selected)
        {
            if (!list.Contains(method)) list.Add(method);
        }
        else list.Remove(method);
        model.DefaultAllowedMfaMethods = list.Any() ? System.Text.Json.JsonSerializer.Serialize(list) : null;
    }

    internal async Task OnSave(UpdateRealmDefaultsRequest formModel)
    {
        try
        {
            var updated = await RealmsApiService.UpdateRealmDefaultsAsync(Id!, formModel);
            if (updated != null)
            {
                NotificationService.Notify(NotificationSeverity.Success, "Success", "Realm defaults saved");
                Navigation.NavigateTo($"/realms/edit/{Id}");
            }
            else NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to save realm defaults");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error saving realm defaults");
            NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to save realm default configuration");
        }
    }

    internal async Task ResetToSystemDefaults()
    {
        var ok = await DialogService.Confirm("Reset all realm defaults to system-wide defaults?", "Reset to System Defaults", new ConfirmOptions() { OkButtonText = "Reset", CancelButtonText = "Cancel" });
        if (ok != true) return;
        // Token lifetimes
        model.AccessTokenLifetime = MrWho.Shared.MrWhoConstants.TokenLifetimes.AccessToken;
        model.RefreshTokenLifetime = MrWho.Shared.MrWhoConstants.TokenLifetimes.RefreshToken;
        model.AuthorizationCodeLifetime = MrWho.Shared.MrWhoConstants.TokenLifetimes.AuthorizationCode;
        model.IdTokenLifetime = TimeSpan.FromMinutes(60);
        model.DeviceCodeLifetime = TimeSpan.FromMinutes(10);

        // Other defaults
        model.DefaultSessionTimeoutHours = 8;
        model.DefaultRememberMeDurationDays = 30;
        model.DefaultUseSlidingSessionExpiration = true;
        model.DefaultCookieSameSitePolicy = "Lax";
        model.DefaultRequireHttpsForCookies = false;
        model.DefaultRequireConsent = false;
        model.DefaultAllowRememberConsent = true;
        model.DefaultMaxRefreshTokensPerUser = null;
        model.DefaultUseOneTimeRefreshTokens = false;
        model.DefaultIncludeJwtId = true;
        model.DefaultRequireMfa = false;
        model.DefaultMfaGracePeriodMinutes = null;
        model.DefaultAllowedMfaMethods = System.Text.Json.JsonSerializer.Serialize(new[] { "totp", "sms" });
        model.DefaultRememberMfaForSession = true;
        model.DefaultRateLimitRequestsPerMinute = null;
        model.DefaultRateLimitRequestsPerHour = null;
        model.DefaultRateLimitRequestsPerDay = null;
        model.DefaultEnableDetailedErrors = false;
        model.DefaultLogSensitiveData = false;
        model.DefaultThemeName = null;
        NotificationService.Notify(NotificationSeverity.Info, "Reset", "Configuration reset to system defaults");
    }

    internal void BackToRealm() => Navigation.NavigateTo("/realms");
    internal void PickTheme(string? name) => model.DefaultThemeName = name;

    internal record DropdownItem<T>(string Text, T Value);
}
