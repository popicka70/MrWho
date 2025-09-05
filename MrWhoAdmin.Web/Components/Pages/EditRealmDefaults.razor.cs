using Microsoft.AspNetCore.Components;
using MrWho.Shared.Models;
using Radzen;
using MrWhoAdmin.Web.Services;

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
    internal string? realmDisplayName; // new: holds realm name for UI

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

    private async Task LoadRealmDefaults()
    {
        isLoading = true;
        try
        {
            var realm = await RealmsApiService.GetRealmAsync(Id!);
            if (realm != null)
            {
                model = MapRealmToDefaultsRequest(realm);
                // Build display string: Prefer DisplayName; include technical name if different
                if (!string.IsNullOrWhiteSpace(realm.DisplayName) && !string.Equals(realm.DisplayName, realm.Name, StringComparison.OrdinalIgnoreCase))
                {
                    realmDisplayName = $"{realm.DisplayName} ({realm.Name})";
                }
                else
                {
                    realmDisplayName = realm.Name;
                }
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
        DefaultSessionTimeoutHours = realm.DefaultSessionTimeoutHours,
        DefaultRememberMeDurationDays = realm.DefaultRememberMeDurationDays,
        DefaultUseSlidingSessionExpiration = realm.DefaultUseSlidingSessionExpiration,
        DefaultCookieSameSitePolicy = realm.DefaultCookieSameSitePolicy,
        DefaultRequireHttpsForCookies = realm.DefaultRequireHttpsForCookies,
        DefaultRequireConsent = realm.DefaultRequireConsent,
        DefaultAllowRememberConsent = realm.DefaultAllowRememberConsent,
        DefaultMaxRefreshTokensPerUser = realm.DefaultMaxRefreshTokensPerUser,
        DefaultUseOneTimeRefreshTokens = realm.DefaultUseOneTimeRefreshTokens,
        DefaultIncludeJwtId = realm.DefaultIncludeJwtId,
        DefaultRequireMfa = realm.DefaultRequireMfa,
        DefaultMfaGracePeriodMinutes = realm.DefaultMfaGracePeriodMinutes,
        DefaultAllowedMfaMethods = realm.DefaultAllowedMfaMethods,
        DefaultRememberMfaForSession = realm.DefaultRememberMfaForSession,
        DefaultRateLimitRequestsPerMinute = realm.DefaultRateLimitRequestsPerMinute,
        DefaultRateLimitRequestsPerHour = realm.DefaultRateLimitRequestsPerHour,
        DefaultRateLimitRequestsPerDay = realm.DefaultRateLimitRequestsPerDay,
        DefaultEnableDetailedErrors = realm.DefaultEnableDetailedErrors,
        DefaultLogSensitiveData = realm.DefaultLogSensitiveData,
        DefaultThemeName = realm.DefaultThemeName,
        RealmCustomCssUrl = realm.RealmCustomCssUrl,
        RealmLogoUri = realm.RealmLogoUri,
        RealmUri = realm.RealmUri,
        RealmPolicyUri = realm.RealmPolicyUri,
        RealmTosUri = realm.RealmTosUri
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
        var ok = await DialogService.Confirm("Reset all realm defaults to system-wide defaults?", "Reset to System Defaults", new ConfirmOptions(){OkButtonText="Reset",CancelButtonText="Cancel"});
        if (ok != true) return;
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
