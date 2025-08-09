using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class AddDynamicClientConfiguration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "DefaultAllowRememberConsent",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "DefaultAllowedMfaMethods",
                table: "Realms",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DefaultCookieSameSitePolicy",
                table: "Realms",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "DefaultEnableDetailedErrors",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultIncludeJwtId",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultLogSensitiveData",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "DefaultMaxRefreshTokensPerUser",
                table: "Realms",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DefaultMfaGracePeriodMinutes",
                table: "Realms",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DefaultRateLimitRequestsPerDay",
                table: "Realms",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DefaultRateLimitRequestsPerHour",
                table: "Realms",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DefaultRateLimitRequestsPerMinute",
                table: "Realms",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DefaultRememberMeDurationDays",
                table: "Realms",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultRememberMfaForSession",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultRequireConsent",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultRequireHttpsForCookies",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultRequireMfa",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "DefaultSessionTimeoutHours",
                table: "Realms",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "DefaultThemeName",
                table: "Realms",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultUseOneTimeRefreshTokens",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "DefaultUseSlidingSessionExpiration",
                table: "Realms",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<TimeSpan>(
                name: "DeviceCodeLifetime",
                table: "Realms",
                type: "time",
                nullable: false,
                defaultValue: new TimeSpan(0, 0, 0, 0, 0));

            migrationBuilder.AddColumn<TimeSpan>(
                name: "IdTokenLifetime",
                table: "Realms",
                type: "time",
                nullable: false,
                defaultValue: new TimeSpan(0, 0, 0, 0, 0));

            migrationBuilder.AddColumn<string>(
                name: "RealmCustomCssUrl",
                table: "Realms",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RealmLogoUri",
                table: "Realms",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RealmPolicyUri",
                table: "Realms",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RealmTosUri",
                table: "Realms",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RealmUri",
                table: "Realms",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AccessTokenType",
                table: "Clients",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowAccessToIntrospectionEndpoint",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowAccessToRevocationEndpoint",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowAccessToUserInfoEndpoint",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowRememberConsent",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AllowedCorsOrigins",
                table: "Clients",
                type: "nvarchar(4000)",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AllowedIdentityProviders",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AllowedMfaMethods",
                table: "Clients",
                type: "nvarchar(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AlwaysIncludeUserClaimsInIdToken",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AlwaysSendClientClaims",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "BackChannelLogoutSessionRequired",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BackChannelLogoutUri",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ClientClaimsPrefix",
                table: "Clients",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ClientUri",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CookieSameSitePolicy",
                table: "Clients",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CustomCssUrl",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CustomErrorPageUrl",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CustomJavaScriptUrl",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CustomLoginPageUrl",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CustomLogoutPageUrl",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DeviceCodeLifetimeMinutes",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DeviceCodePollingIntervalSeconds",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "EnableDetailedErrors",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "EnableLocalLogin",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "FrontChannelLogoutSessionRequired",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "FrontChannelLogoutUri",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "HashAccessTokens",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "IdTokenLifetimeMinutes",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IncludeJwtId",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "LogSensitiveData",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LogoUri",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "MaxRefreshTokensPerUser",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "MfaGracePeriodMinutes",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PageTitlePrefix",
                table: "Clients",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "PairWiseSubjectSalt",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PolicyUri",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProtocolType",
                table: "Clients",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RateLimitRequestsPerDay",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RateLimitRequestsPerHour",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RateLimitRequestsPerMinute",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RememberMeDurationDays",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RememberMfaForSession",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequireConsent",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequireHttpsForCookies",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequireMfa",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SessionTimeoutHours",
                table: "Clients",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ShowClientLogo",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ThemeName",
                table: "Clients",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TosUri",
                table: "Clients",
                type: "nvarchar(2000)",
                maxLength: 2000,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "UpdateAccessTokenClaimsOnRefresh",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "UseOneTimeRefreshTokens",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "UseSlidingSessionExpiration",
                table: "Clients",
                type: "bit",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UserCodeType",
                table: "Clients",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DefaultAllowRememberConsent",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultAllowedMfaMethods",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultCookieSameSitePolicy",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultEnableDetailedErrors",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultIncludeJwtId",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultLogSensitiveData",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultMaxRefreshTokensPerUser",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultMfaGracePeriodMinutes",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRateLimitRequestsPerDay",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRateLimitRequestsPerHour",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRateLimitRequestsPerMinute",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRememberMeDurationDays",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRememberMfaForSession",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRequireConsent",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRequireHttpsForCookies",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultRequireMfa",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultSessionTimeoutHours",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultThemeName",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultUseOneTimeRefreshTokens",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DefaultUseSlidingSessionExpiration",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "DeviceCodeLifetime",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "IdTokenLifetime",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "RealmCustomCssUrl",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "RealmLogoUri",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "RealmPolicyUri",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "RealmTosUri",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "RealmUri",
                table: "Realms");

            migrationBuilder.DropColumn(
                name: "AccessTokenType",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowAccessToIntrospectionEndpoint",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowAccessToRevocationEndpoint",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowAccessToUserInfoEndpoint",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowRememberConsent",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowedCorsOrigins",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowedIdentityProviders",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowedMfaMethods",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AlwaysIncludeUserClaimsInIdToken",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AlwaysSendClientClaims",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "BackChannelLogoutSessionRequired",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "BackChannelLogoutUri",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ClientClaimsPrefix",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ClientUri",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "CookieSameSitePolicy",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "CustomCssUrl",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "CustomErrorPageUrl",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "CustomJavaScriptUrl",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "CustomLoginPageUrl",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "CustomLogoutPageUrl",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "DeviceCodeLifetimeMinutes",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "DeviceCodePollingIntervalSeconds",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "EnableDetailedErrors",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "EnableLocalLogin",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "FrontChannelLogoutSessionRequired",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "FrontChannelLogoutUri",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "HashAccessTokens",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "IdTokenLifetimeMinutes",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "IncludeJwtId",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "LogSensitiveData",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "LogoUri",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "MaxRefreshTokensPerUser",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "MfaGracePeriodMinutes",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "PageTitlePrefix",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "PairWiseSubjectSalt",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "PolicyUri",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ProtocolType",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RateLimitRequestsPerDay",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RateLimitRequestsPerHour",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RateLimitRequestsPerMinute",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RememberMeDurationDays",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RememberMfaForSession",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RequireConsent",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RequireHttpsForCookies",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RequireMfa",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "SessionTimeoutHours",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ShowClientLogo",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ThemeName",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "TosUri",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "UpdateAccessTokenClaimsOnRefresh",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "UseOneTimeRefreshTokens",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "UseSlidingSessionExpiration",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "UserCodeType",
                table: "Clients");
        }
    }
}
