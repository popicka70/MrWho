using MrWho.Shared;
using MrWho.Shared.Models;
using Radzen;

namespace MrWhoAdmin.Web.Components.Pages
{
    public partial class EditClient
    {
        internal CreateClientRequest model = new();
        internal List<RealmDto> realms = new();
        internal List<ScopeDto> availableScopes = new();
        internal List<ScopeSelection> scopeItems = new();
        internal string? scopeSearch;
        private bool isLoading = false; // stays private (only used in main page)
        internal bool IsLoading => isLoading; // expose read-only to tab components
        private int selectedTabIndex = 0; // stays private (only used in main page)

        // Dropdown data
        internal List<DropdownItem<ClientType>> clientTypes = new();
        internal List<DropdownItem<string>> sameSitePolicies = new();
        internal List<DropdownItem<string>> accessTokenTypes = new();
        internal List<DropdownItem<bool?>> triStateOptions = new();
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

        // Selections
        internal List<string> selectedScopes = new();
        internal List<string> selectedPermissions = new();
        internal List<string> selectedAudiences = new();
        public IReadOnlyList<string> SelectedAudiences => selectedAudiences;
        public void SetAudiences(List<string> audiences)
        {
            selectedAudiences = audiences ?? new();
            StateHasChanged();
        }

        // Multi-line text backing for URIs
        internal string redirectUrisText = string.Empty;
        internal string postLogoutUrisText = string.Empty;

        // Convenience binding for MFA methods serialization (use model's value)
        private string? allowedMfaMethodsSerialized => model.AllowedMfaMethods;

        // Identity Provider links state
        internal List<ClientIdentityProviderDto> identityLinks = new();
        internal List<IdentityProviderDto> providers = new();
        internal string? selectedProviderId;
        internal string providerSearch = string.Empty;
        internal string? linkDisplayOverride;
        internal int? linkOrder;
        internal bool linkEnabled = true;

        internal bool IsEdit => !string.IsNullOrEmpty(Id);

        protected override async Task OnInitializedAsync()
        {
            await LoadRealms();
            await LoadScopes();
            InitializeDropdownData();

            if (IsEdit && !string.IsNullOrEmpty(Id))
            {
                await LoadClient();
                await ReloadProviders();
                await LoadIdentityLinksAsync();
            }
            else
            {
                // Set defaults for new client
                model.IsEnabled = true;
                model.AllowAuthorizationCodeFlow = true;
                model.AllowRefreshTokenFlow = true;
                model.AllowClientCredentialsFlow = false;
                model.AllowPasswordFlow = false;
                model.RequirePkce = model.ClientType != ClientType.Machine;
                model.RequireClientSecret = model.ClientType != ClientType.Public;
                model.UseSlidingSessionExpiration = true;
                model.AllowAccessToUserInfoEndpoint = true;
                model.AllowAccessToRevocationEndpoint = true;
                model.RememberMfaForSession = true;
                model.EnableLocalLogin = true;
                // Login option defaults
                model.AllowPasskeyLogin = true;
                model.AllowQrLoginQuick = true;
                model.AllowQrLoginSecure = true;
                model.AllowCodeLogin = true;
                // Reasonable default scopes for new client
                selectedScopes = new() { "openid", "profile", "email", "roles", "offline_access" };
            }
        }

        private void InitializeDropdownData()
        {
            clientTypes = new()
        {
            new("Confidential", ClientType.Confidential),
            new("Public", ClientType.Public),
            new("Machine", ClientType.Machine)
        };

            sameSitePolicies = new()
        {
            new("None (Cross-site requests allowed)", "None"),
            new("Lax (Some cross-site requests)", "Lax"),
            new("Strict (No cross-site requests)", "Strict")
        };

            accessTokenTypes = new()
        {
            new("JWT (Self-contained)", "JWT"),
            new("Reference (Database lookup)", "Reference")
        };

            triStateOptions = new()
        {
            new("Use realm default", null),
            new("Enabled", true),
            new("Disabled", false)
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

        private async Task LoadRealms()
        {
            try
            {
                var result = await RealmsApiService.GetRealmsAsync(1, 100);
                realms = result?.Items ?? new List<RealmDto>();
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error loading realms");
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to load realms");
            }
        }

        private async Task LoadScopes()
        {
            try
            {
                var result = await ScopesApiService.GetScopesAsync(1, 1000);
                availableScopes = result?.Items ?? new List<ScopeDto>();
                BuildScopeSelections();
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error loading scopes");
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to load scopes");
            }
        }

        private CreateClientRequest MapClientToRequest(ClientDto client)
        {
            return new CreateClientRequest
            {
                ClientId = client.ClientId,
                Name = client.Name,
                Description = client.Description,
                IsEnabled = client.IsEnabled,
                RealmId = client.RealmId,
                ClientType = client.ClientType,
                // Flow/grant fields
                AllowAuthorizationCodeFlow = client.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = client.AllowClientCredentialsFlow,
                AllowPasswordFlow = client.AllowPasswordFlow,
                AllowRefreshTokenFlow = client.AllowRefreshTokenFlow,
                AllowDeviceCodeFlow = client.AllowDeviceCodeFlow,
                RequirePkce = client.RequirePkce,
                RequireClientSecret = client.ClientType != ClientType.Public,
                // Dynamic fields
                SessionTimeoutHours = client.SessionTimeoutHours,
                UseSlidingSessionExpiration = client.UseSlidingSessionExpiration,
                RememberMeDurationDays = client.RememberMeDurationDays,
                RequireHttpsForCookies = client.RequireHttpsForCookies,
                CookieSameSitePolicy = client.CookieSameSitePolicy,
                IdTokenLifetimeMinutes = client.IdTokenLifetimeMinutes,
                DeviceCodeLifetimeMinutes = client.DeviceCodeLifetimeMinutes,
                AccessTokenType = client.AccessTokenType,
                UseOneTimeRefreshTokens = client.UseOneTimeRefreshTokens,
                MaxRefreshTokensPerUser = client.MaxRefreshTokensPerUser,
                HashAccessTokens = client.HashAccessTokens,
                UpdateAccessTokenClaimsOnRefresh = client.UpdateAccessTokenClaimsOnRefresh,
                RequireConsent = client.RequireConsent,
                AllowRememberConsent = client.AllowRememberConsent,
                AllowAccessToUserInfoEndpoint = client.AllowAccessToUserInfoEndpoint,
                AllowAccessToIntrospectionEndpoint = client.AllowAccessToIntrospectionEndpoint,
                AllowAccessToRevocationEndpoint = client.AllowAccessToRevocationEndpoint,
                IncludeJwtId = client.IncludeJwtId,
                AlwaysSendClientClaims = client.AlwaysSendClientClaims,
                AlwaysIncludeUserClaimsInIdToken = client.AlwaysIncludeUserClaimsInIdToken,
                ClientClaimsPrefix = client.ClientClaimsPrefix,
                RequireMfa = client.RequireMfa,
                MfaGracePeriodMinutes = client.MfaGracePeriodMinutes,
                AllowedMfaMethods = client.AllowedMfaMethods,
                RememberMfaForSession = client.RememberMfaForSession,
                RateLimitRequestsPerMinute = client.RateLimitRequestsPerMinute,
                RateLimitRequestsPerHour = client.RateLimitRequestsPerHour,
                RateLimitRequestsPerDay = client.RateLimitRequestsPerDay,
                ThemeName = client.ThemeName,
                CustomCssUrl = client.CustomCssUrl,
                CustomJavaScriptUrl = client.CustomJavaScriptUrl,
                PageTitlePrefix = client.PageTitlePrefix,
                LogoUri = client.LogoUri,
                ClientUri = client.ClientUri,
                PolicyUri = client.PolicyUri,
                TosUri = client.TosUri,
                BackChannelLogoutUri = client.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = client.BackChannelLogoutSessionRequired,
                FrontChannelLogoutUri = client.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = client.FrontChannelLogoutSessionRequired,
                AllowedCorsOrigins = client.AllowedCorsOrigins,
                AllowedIdentityProviders = client.AllowedIdentityProviders,
                ProtocolType = client.ProtocolType,
                EnableDetailedErrors = client.EnableDetailedErrors,
                LogSensitiveData = client.LogSensitiveData,
                EnableLocalLogin = client.EnableLocalLogin,
                CustomLoginPageUrl = client.CustomLoginPageUrl,
                CustomLogoutPageUrl = client.CustomLogoutPageUrl,
                CustomErrorPageUrl = client.CustomErrorPageUrl,
                // New login options
                AllowPasskeyLogin = client.AllowPasskeyLogin,
                AllowQrLoginQuick = client.AllowQrLoginQuick,
                AllowQrLoginSecure = client.AllowQrLoginSecure,
                AllowCodeLogin = client.AllowCodeLogin,
                // Audience configuration
                AudienceMode = client.AudienceMode,
                PrimaryAudience = client.PrimaryAudience,
                IncludeAudInIdToken = client.IncludeAudInIdToken,
                RequireExplicitAudienceScope = client.RequireExplicitAudienceScope,
                RoleInclusionOverride = client.RoleInclusionOverride
            };
        }

        private UpdateClientRequest BuildUpdateRequestFromModel()
        {
            var update = new UpdateClientRequest
            {
                Name = model.Name,
                Description = model.Description,
                IsEnabled = model.IsEnabled,
                ClientType = model.ClientType,
                AllowAuthorizationCodeFlow = model.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = model.AllowClientCredentialsFlow,
                AllowPasswordFlow = model.AllowPasswordFlow,
                AllowRefreshTokenFlow = model.AllowRefreshTokenFlow,
                AllowDeviceCodeFlow = model.AllowDeviceCodeFlow,
                RequirePkce = model.RequirePkce,
                RequireClientSecret = model.RequireClientSecret,
                RedirectUris = redirectUrisText?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList() ?? new(),
                PostLogoutUris = postLogoutUrisText?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList() ?? new(),
                Scopes = selectedScopes,
                Permissions = selectedPermissions,
                Audiences = selectedAudiences,
                SessionTimeoutHours = model.SessionTimeoutHours,
                UseSlidingSessionExpiration = model.UseSlidingSessionExpiration,
                RememberMeDurationDays = model.RememberMeDurationDays,
                RequireHttpsForCookies = model.RequireHttpsForCookies,
                CookieSameSitePolicy = model.CookieSameSitePolicy,
                IdTokenLifetimeMinutes = model.IdTokenLifetimeMinutes,
                DeviceCodeLifetimeMinutes = model.DeviceCodeLifetimeMinutes,
                AccessTokenType = model.AccessTokenType,
                UseOneTimeRefreshTokens = model.UseOneTimeRefreshTokens,
                MaxRefreshTokensPerUser = model.MaxRefreshTokensPerUser,
                HashAccessTokens = model.HashAccessTokens,
                UpdateAccessTokenClaimsOnRefresh = model.UpdateAccessTokenClaimsOnRefresh,
                RequireConsent = model.RequireConsent,
                AllowRememberConsent = model.AllowRememberConsent,
                AllowAccessToUserInfoEndpoint = model.AllowAccessToUserInfoEndpoint,
                AllowAccessToIntrospectionEndpoint = model.AllowAccessToIntrospectionEndpoint,
                AllowAccessToRevocationEndpoint = model.AllowAccessToRevocationEndpoint,
                IncludeJwtId = model.IncludeJwtId,
                AlwaysSendClientClaims = model.AlwaysSendClientClaims,
                AlwaysIncludeUserClaimsInIdToken = model.AlwaysIncludeUserClaimsInIdToken,
                ClientClaimsPrefix = model.ClientClaimsPrefix,
                RequireMfa = model.RequireMfa,
                MfaGracePeriodMinutes = model.MfaGracePeriodMinutes,
                AllowedMfaMethods = model.AllowedMfaMethods,
                RememberMfaForSession = model.RememberMfaForSession,
                RateLimitRequestsPerMinute = model.RateLimitRequestsPerMinute,
                RateLimitRequestsPerHour = model.RateLimitRequestsPerHour,
                RateLimitRequestsPerDay = model.RateLimitRequestsPerDay,
                ThemeName = model.ThemeName,
                CustomCssUrl = model.CustomCssUrl,
                CustomJavaScriptUrl = model.CustomJavaScriptUrl,
                PageTitlePrefix = model.PageTitlePrefix,
                LogoUri = model.LogoUri,
                ClientUri = model.ClientUri,
                PolicyUri = model.PolicyUri,
                TosUri = model.TosUri,
                BackChannelLogoutUri = model.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = model.BackChannelLogoutSessionRequired,
                FrontChannelLogoutUri = model.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = model.FrontChannelLogoutSessionRequired,
                AllowedCorsOrigins = model.AllowedCorsOrigins,
                AllowedIdentityProviders = model.AllowedIdentityProviders,
                ProtocolType = model.ProtocolType,
                EnableDetailedErrors = model.EnableDetailedErrors,
                LogSensitiveData = model.LogSensitiveData,
                EnableLocalLogin = model.EnableLocalLogin,
                CustomLoginPageUrl = model.CustomLoginPageUrl,
                CustomLogoutPageUrl = model.CustomLogoutPageUrl,
                CustomErrorPageUrl = model.CustomErrorPageUrl,
                // New login options
                AllowPasskeyLogin = model.AllowPasskeyLogin,
                AllowQrLoginQuick = model.AllowQrLoginQuick,
                AllowQrLoginSecure = model.AllowQrLoginSecure,
                AllowCodeLogin = model.AllowCodeLogin,
                // Audience configuration
                AudienceMode = model.AudienceMode,
                PrimaryAudience = model.PrimaryAudience,
                IncludeAudInIdToken = model.IncludeAudInIdToken,
                RequireExplicitAudienceScope = model.RequireExplicitAudienceScope,
                RoleInclusionOverride = model.RoleInclusionOverride
            };
            update.ClientSecret = string.IsNullOrWhiteSpace(model.ClientSecret) ? null : model.ClientSecret;
            return update;
        }

        private CreateClientRequest BuildCreateRequestFromModel()
        {
            return new CreateClientRequest
            {
                ClientId = model.ClientId,
                ClientSecret = model.ClientSecret,
                Name = model.Name,
                Description = model.Description,
                RealmId = model.RealmId,
                IsEnabled = model.IsEnabled,
                ClientType = model.ClientType,
                AllowAuthorizationCodeFlow = model.AllowAuthorizationCodeFlow,
                AllowClientCredentialsFlow = model.AllowClientCredentialsFlow,
                AllowPasswordFlow = model.AllowPasswordFlow,
                AllowRefreshTokenFlow = model.AllowRefreshTokenFlow,
                AllowDeviceCodeFlow = model.AllowDeviceCodeFlow,
                RequirePkce = model.RequirePkce,
                RequireClientSecret = model.RequireClientSecret,
                RedirectUris = redirectUrisText?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList() ?? new(),
                PostLogoutUris = postLogoutUrisText?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList() ?? new(),
                Scopes = selectedScopes,
                Permissions = selectedPermissions,
                Audiences = selectedAudiences,
                SessionTimeoutHours = model.SessionTimeoutHours,
                UseSlidingSessionExpiration = model.UseSlidingSessionExpiration,
                RememberMeDurationDays = model.RememberMeDurationDays,
                RequireHttpsForCookies = model.RequireHttpsForCookies,
                CookieSameSitePolicy = model.CookieSameSitePolicy,
                IdTokenLifetimeMinutes = model.IdTokenLifetimeMinutes,
                DeviceCodeLifetimeMinutes = model.DeviceCodeLifetimeMinutes,
                AccessTokenType = model.AccessTokenType,
                UseOneTimeRefreshTokens = model.UseOneTimeRefreshTokens,
                MaxRefreshTokensPerUser = model.MaxRefreshTokensPerUser,
                HashAccessTokens = model.HashAccessTokens,
                UpdateAccessTokenClaimsOnRefresh = model.UpdateAccessTokenClaimsOnRefresh,
                RequireConsent = model.RequireConsent,
                AllowRememberConsent = model.AllowRememberConsent,
                AllowAccessToUserInfoEndpoint = model.AllowAccessToUserInfoEndpoint,
                AllowAccessToIntrospectionEndpoint = model.AllowAccessToIntrospectionEndpoint,
                AllowAccessToRevocationEndpoint = model.AllowAccessToRevocationEndpoint,
                IncludeJwtId = model.IncludeJwtId,
                AlwaysSendClientClaims = model.AlwaysSendClientClaims,
                AlwaysIncludeUserClaimsInIdToken = model.AlwaysIncludeUserClaimsInIdToken,
                ClientClaimsPrefix = model.ClientClaimsPrefix,
                RequireMfa = model.RequireMfa,
                MfaGracePeriodMinutes = model.MfaGracePeriodMinutes,
                AllowedMfaMethods = model.AllowedMfaMethods,
                RememberMfaForSession = model.RememberMfaForSession,
                RateLimitRequestsPerMinute = model.RateLimitRequestsPerMinute,
                RateLimitRequestsPerHour = model.RateLimitRequestsPerHour,
                RateLimitRequestsPerDay = model.RateLimitRequestsPerDay,
                ThemeName = model.ThemeName,
                CustomCssUrl = model.CustomCssUrl,
                CustomJavaScriptUrl = model.CustomJavaScriptUrl,
                PageTitlePrefix = model.PageTitlePrefix,
                LogoUri = model.LogoUri,
                ClientUri = model.ClientUri,
                PolicyUri = model.PolicyUri,
                TosUri = model.TosUri,
                BackChannelLogoutUri = model.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = model.BackChannelLogoutSessionRequired,
                FrontChannelLogoutUri = model.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = model.FrontChannelLogoutSessionRequired,
                AllowedCorsOrigins = model.AllowedCorsOrigins,
                AllowedIdentityProviders = model.AllowedIdentityProviders,
                ProtocolType = model.ProtocolType,
                EnableDetailedErrors = model.EnableDetailedErrors,
                LogSensitiveData = model.LogSensitiveData,
                EnableLocalLogin = model.EnableLocalLogin,
                CustomLoginPageUrl = model.CustomLoginPageUrl,
                CustomLogoutPageUrl = model.CustomLogoutPageUrl,
                CustomErrorPageUrl = model.CustomErrorPageUrl,
                // New login options
                AllowPasskeyLogin = model.AllowPasskeyLogin,
                AllowQrLoginQuick = model.AllowQrLoginQuick,
                AllowQrLoginSecure = model.AllowQrLoginSecure,
                AllowCodeLogin = model.AllowCodeLogin,
                // Audience configuration
                AudienceMode = model.AudienceMode,
                PrimaryAudience = model.PrimaryAudience,
                IncludeAudInIdToken = model.IncludeAudInIdToken,
                RequireExplicitAudienceScope = model.RequireExplicitAudienceScope,
                RoleInclusionOverride = model.RoleInclusionOverride
            };
        }

        private async Task LoadClient()
        {
            isLoading = true;
            try
            {
                var client = await ClientsApiService.GetClientAsync(Id!);
                if (client != null)
                {
                    model = MapClientToRequest(client);
                    redirectUrisText = string.Join("\n", client.RedirectUris ?? new());
                    postLogoutUrisText = string.Join("\n", client.PostLogoutUris ?? new());
                    selectedScopes = client.Scopes?.ToList() ?? new();
                    selectedPermissions = client.Permissions?.ToList() ?? new();
                    selectedAudiences = client.Audiences?.ToList() ?? new();
                    BuildScopeSelections();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error loading client {ClientId}", Id);
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to load client");
            }
            finally
            {
                isLoading = false;
            }
        }

        internal async Task ReloadProviders()
        {
            try
            {
                // Load providers optionally filtered by realm
                providers = await IdentityProvidersApi.GetIdentityProvidersAsync(model.RealmId) ?? new();
                StateHasChanged();
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error loading identity providers for realm {RealmId}", model.RealmId);
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to load identity providers");
            }
        }

        internal IEnumerable<IdentityProviderDto> FilteredProviders => string.IsNullOrWhiteSpace(providerSearch)
            ? providers
            : providers.Where(p => ((p.DisplayName ?? p.Name)?.Contains(providerSearch, StringComparison.OrdinalIgnoreCase) ?? false)
                                || p.Name.Contains(providerSearch, StringComparison.OrdinalIgnoreCase));

        internal string GetProviderName(string providerId)
        {
            var p = providers.FirstOrDefault(x => x.Id == providerId);
            return p?.DisplayName ?? p?.Name ?? providerId;
        }

        private async Task LoadIdentityLinksAsync()
        {
            try
            {
                identityLinks = await ClientsApiService.GetIdentityLinksAsync(Id!);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Error loading identity links for client {ClientId}", Id);
                identityLinks = new();
            }
        }

        internal async Task AddIdentityLink()
        {
            if (!IsEdit || string.IsNullOrEmpty(selectedProviderId)) return;
            try
            {
                var dto = new ClientIdentityProviderDto
                {
                    DisplayNameOverride = linkDisplayOverride,
                    Order = linkOrder,
                    IsEnabled = linkEnabled
                };
                var created = await ClientsApiService.AddIdentityLinkAsync(Id!, selectedProviderId!, dto);
                if (created is not null)
                {
                    NotificationService.Notify(new NotificationMessage { Severity = NotificationSeverity.Success, Summary = "Linked" });
                    linkDisplayOverride = null;
                    linkOrder = null;
                    linkEnabled = true;
                    selectedProviderId = null;
                    await LoadIdentityLinksAsync();
                }
                else
                {
                    NotificationService.Notify(new NotificationMessage { Severity = NotificationSeverity.Error, Summary = "Link failed" });
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "AddIdentityLink failed for client {ClientId}", Id);
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Link failed");
            }
        }

        internal async Task RemoveIdentityLink(ClientIdentityProviderDto link)
        {
            try
            {
                var ok = await ClientsApiService.RemoveIdentityLinkAsync(Id!, link.Id);
                if (ok)
                {
                    NotificationService.Notify(new NotificationMessage { Severity = NotificationSeverity.Info, Summary = "Removed" });
                    await LoadIdentityLinksAsync();
                }
                else
                {
                    NotificationService.Notify(new NotificationMessage { Severity = NotificationSeverity.Error, Summary = "Remove failed" });
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "RemoveIdentityLink failed for client {ClientId}", Id);
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Remove failed");
            }
        }

        internal bool IsMethodSelected(string method)
        {
            if (string.IsNullOrEmpty(model.AllowedMfaMethods))
                return false;
            try
            {
                var methods = System.Text.Json.JsonSerializer.Deserialize<string[]>(model.AllowedMfaMethods);
                return methods?.Contains(method) == true;
            }
            catch { return false; }
        }

        internal void ToggleMfaMethod(string method, bool selected)
        {
            var methods = new List<string>();
            if (!string.IsNullOrEmpty(model.AllowedMfaMethods))
            {
                try
                {
                    var existing = System.Text.Json.JsonSerializer.Deserialize<string[]>(model.AllowedMfaMethods);
                    if (existing != null) methods.AddRange(existing);
                }
                catch { }
            }
            if (selected)
            {
                if (!methods.Contains(method)) methods.Add(method);
            }
            else
            {
                methods.Remove(method);
            }
            model.AllowedMfaMethods = methods.Any() ? System.Text.Json.JsonSerializer.Serialize(methods.ToArray()) : null;
        }

        private async Task OnSave(CreateClientRequest args)
        {
            ClientDto? result;
            if (IsEdit)
            {
                var update = BuildUpdateRequestFromModel();
                result = await ClientsApiService.UpdateClientAsync(Id!, update);
                if (result != null)
                {
                    var fresh = await ClientsApiService.GetClientAsync(result.Id);
                    if (fresh != null)
                    {
                        result = fresh;
                    }
                }
            }
            else
            {
                result = await ClientsApiService.CreateClientAsync(BuildCreateRequestFromModel());
            }

            if (result != null)
            {
                NotificationService.Notify(NotificationSeverity.Success, "Success", $"Client '{result.Name}' has been {(IsEdit ? "updated" : "created")} successfully");
                Navigation.NavigateTo("/clients");
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to save client");
            }
        }

        private void CancelEdit() => Navigation.NavigateTo("/clients");

        private Task ResetToDefaults()
        {
            model.SessionTimeoutHours = null;
            model.UseSlidingSessionExpiration = null;
            model.RememberMeDurationDays = null;
            model.RequireHttpsForCookies = null;
            model.CookieSameSitePolicy = null;
            model.IdTokenLifetimeMinutes = null;
            model.DeviceCodeLifetimeMinutes = null;
            model.AccessTokenType = null;
            model.UseOneTimeRefreshTokens = null;
            model.MaxRefreshTokensPerUser = null;
            model.HashAccessTokens = null;
            model.UpdateAccessTokenClaimsOnRefresh = null;
            model.RequireConsent = null;
            model.AllowRememberConsent = null;
            model.AllowAccessToUserInfoEndpoint = null;
            model.AllowAccessToIntrospectionEndpoint = null;
            model.AllowAccessToRevocationEndpoint = null;
            model.IncludeJwtId = null;
            model.AlwaysSendClientClaims = null;
            model.AlwaysIncludeUserClaimsInIdToken = null;
            model.ClientClaimsPrefix = null;
            model.RequireMfa = null;
            model.MfaGracePeriodMinutes = null;
            model.AllowedMfaMethods = null;
            model.RememberMfaForSession = null;
            model.RateLimitRequestsPerMinute = null;
            model.RateLimitRequestsPerHour = null;
            model.RateLimitRequestsPerDay = null;
            model.ThemeName = null;
            model.CustomCssUrl = null;
            model.CustomJavaScriptUrl = null;
            model.PageTitlePrefix = null;
            model.LogoUri = null;
            model.ClientUri = null;
            model.PolicyUri = null;
            model.TosUri = null;
            model.BackChannelLogoutUri = null;
            model.BackChannelLogoutSessionRequired = null;
            model.FrontChannelLogoutUri = null;
            model.FrontChannelLogoutSessionRequired = null;
            model.AllowedCorsOrigins = null;
            model.AllowedIdentityProviders = null;
            model.EnableLocalLogin = null;
            model.AllowPasskeyLogin = null;
            model.AllowQrLoginQuick = null;
            model.AllowQrLoginSecure = null;
            model.AllowCodeLogin = null;
            StateHasChanged();
            return Task.CompletedTask;
        }

        internal void BuildScopeSelections()
        {
            scopeItems = availableScopes
                .OrderBy(s => s.IsStandard ? 0 : 1)
                .ThenBy(s => s.Name)
                .Select(s => new ScopeSelection
                {
                    Name = s.Name,
                    DisplayName = s.DisplayName,
                    Description = s.Description,
                    Type = s.Type,
                    IsEnabled = s.IsEnabled,
                    IsStandard = s.IsStandard,
                    Selected = selectedScopes?.Contains(s.Name) == true
                })
                .ToList();
        }

        internal void ApplyScopeFilter() => StateHasChanged();

        internal void ToggleScopeSelection(string scopeName, bool selected)
        {
            var item = scopeItems.FirstOrDefault(i => i.Name == scopeName);
            if (item != null) item.Selected = selected;
            if (selected)
            {
                if (!selectedScopes.Contains(scopeName)) selectedScopes.Add(scopeName);
            }
            else
            {
                selectedScopes.Remove(scopeName);
            }
        }

        internal void SelectAllFilteredScopes(bool select)
        {
            foreach (var item in FilteredScopeItems.ToList())
            {
                item.Selected = select;
                if (select)
                {
                    if (!selectedScopes.Contains(item.Name)) selectedScopes.Add(item.Name);
                }
                else
                {
                    selectedScopes.Remove(item.Name);
                }
            }
        }

        internal IEnumerable<ScopeSelection> FilteredScopeItems => string.IsNullOrWhiteSpace(scopeSearch)
            ? scopeItems
            : scopeItems.Where(s => (s.Name?.Contains(scopeSearch, StringComparison.OrdinalIgnoreCase) ?? false)
                                 || (s.DisplayName?.Contains(scopeSearch, StringComparison.OrdinalIgnoreCase) ?? false)
                                 || (s.Description?.Contains(scopeSearch, StringComparison.OrdinalIgnoreCase) ?? false));

        internal record DropdownItem<T>(string Text, T Value);

        internal class ScopeSelection
        {
            public string Name { get; set; } = string.Empty;
            public string? DisplayName { get; set; }
            public string? Description { get; set; }
            public ScopeType Type { get; set; }
            public bool IsEnabled { get; set; }
            public bool IsStandard { get; set; }
            public bool Selected { get; set; }
        }

        internal void GenerateSecret()
        {
            // Generate a 32-byte random secret encoded as Base64Url (no padding)
            var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            var base64 = Convert.ToBase64String(bytes);
            // Make it URL-safe to avoid copy/paste issues in config files if needed
            var urlSafe = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
            model.ClientSecret = urlSafe;
        }
    }
}
