using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ApiResources",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    DisplayName = table.Column<string>(type: "text", nullable: true),
                    Description = table.Column<string>(type: "text", nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsStandard = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true),
                    ClaimDestinationsJson = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiResources", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    NormalizedName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    UserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    NormalizedUserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    NormalizedEmail = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    EmailConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                    PasswordHash = table.Column<string>(type: "text", nullable: true),
                    SecurityStamp = table.Column<string>(type: "text", nullable: true),
                    ConcurrencyStamp = table.Column<string>(type: "text", nullable: true),
                    PhoneNumber = table.Column<string>(type: "text", nullable: true),
                    PhoneNumberConfirmed = table.Column<bool>(type: "boolean", nullable: false),
                    TwoFactorEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    LockoutEnd = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LockoutEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    AccessFailedCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditIntegrityRecords",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(26)", maxLength: 26, nullable: false),
                    TimestampUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Category = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Action = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: false),
                    ActorType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ActorId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    SubjectType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    SubjectId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    RealmId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    DataJson = table.Column<string>(type: "text", nullable: true),
                    PreviousHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    RecordHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditIntegrityRecords", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    OccurredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UserId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    UserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    EntityType = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    EntityId = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Action = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Changes = table.Column<string>(type: "text", nullable: true),
                    RealmId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ClaimTypes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Type = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Category = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    IsStandard = table.Column<bool>(type: "boolean", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsObsolete = table.Column<bool>(type: "boolean", nullable: false),
                    SortOrder = table.Column<int>(type: "integer", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClaimTypes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Consents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false),
                    GrantedScopesJson = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Consents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DataProtectionKeys",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    FriendlyName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Xml = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DataProtectionKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeviceAuthorizations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    DeviceCode = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    UserCode = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Scope = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    Subject = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ApprovedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DeniedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ConsumedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    PollingIntervalSeconds = table.Column<int>(type: "integer", nullable: false),
                    LastPolledAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    VerificationIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    VerificationUserAgent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    MetadataJson = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceAuthorizations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "IdentityResources",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsRequired = table.Column<bool>(type: "boolean", nullable: false),
                    IsStandard = table.Column<bool>(type: "boolean", nullable: false),
                    ShowInDiscoveryDocument = table.Column<bool>(type: "boolean", nullable: false),
                    Emphasize = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IdentityResources", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "KeyMaterials",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Use = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    Kid = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Algorithm = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    KeyType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    PrivateKeyPem = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ActivateAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RetireAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsPrimary = table.Column<bool>(type: "boolean", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KeyMaterials", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OpenIddictApplications",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ApplicationType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ClientId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    ClientSecret = table.Column<string>(type: "text", nullable: true),
                    ClientType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ConcurrencyToken = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ConsentType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    DisplayName = table.Column<string>(type: "text", nullable: true),
                    DisplayNames = table.Column<string>(type: "text", nullable: true),
                    JsonWebKeySet = table.Column<string>(type: "text", nullable: true),
                    Permissions = table.Column<string>(type: "text", nullable: true),
                    PostLogoutRedirectUris = table.Column<string>(type: "text", nullable: true),
                    Properties = table.Column<string>(type: "text", nullable: true),
                    RedirectUris = table.Column<string>(type: "text", nullable: true),
                    Requirements = table.Column<string>(type: "text", nullable: true),
                    Settings = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OpenIddictApplications", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OpenIddictScopes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ConcurrencyToken = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Descriptions = table.Column<string>(type: "text", nullable: true),
                    DisplayName = table.Column<string>(type: "text", nullable: true),
                    DisplayNames = table.Column<string>(type: "text", nullable: true),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Properties = table.Column<string>(type: "text", nullable: true),
                    Resources = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OpenIddictScopes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PendingClientRegistrations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    SubmittedByUserId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    SubmittedByUserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    SubmittedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    ReviewedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ReviewedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ReviewReason = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ClientName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    TokenEndpointAuthMethod = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Scope = table.Column<string>(type: "text", maxLength: 2000, nullable: true),
                    RedirectUrisCsv = table.Column<string>(type: "text", maxLength: 4000, nullable: true),
                    RawRequestJson = table.Column<string>(type: "text", nullable: false),
                    CreatedClientDbId = table.Column<string>(type: "text", nullable: true),
                    CreatedClientPublicId = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PendingClientRegistrations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PushedAuthorizationRequests",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    RequestUri = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ParametersJson = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ParametersHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PushedAuthorizationRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Realms",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    AccessTokenLifetime = table.Column<double>(type: "double precision", nullable: false),
                    RefreshTokenLifetime = table.Column<double>(type: "double precision", nullable: false),
                    AuthorizationCodeLifetime = table.Column<double>(type: "double precision", nullable: false),
                    IdTokenLifetime = table.Column<TimeSpan>(type: "interval", nullable: false),
                    DeviceCodeLifetime = table.Column<TimeSpan>(type: "interval", nullable: false),
                    DefaultSessionTimeoutHours = table.Column<int>(type: "integer", nullable: false),
                    DefaultUseSlidingSessionExpiration = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultRememberMeDurationDays = table.Column<int>(type: "integer", nullable: false),
                    DefaultRequireHttpsForCookies = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultCookieSameSitePolicy = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    DefaultRequireConsent = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultAllowRememberConsent = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultMaxRefreshTokensPerUser = table.Column<int>(type: "integer", nullable: true),
                    DefaultUseOneTimeRefreshTokens = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultIncludeJwtId = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultRequireMfa = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultMfaGracePeriodMinutes = table.Column<int>(type: "integer", nullable: true),
                    DefaultAllowedMfaMethods = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    DefaultRememberMfaForSession = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultRateLimitRequestsPerMinute = table.Column<int>(type: "integer", nullable: true),
                    DefaultRateLimitRequestsPerHour = table.Column<int>(type: "integer", nullable: true),
                    DefaultRateLimitRequestsPerDay = table.Column<int>(type: "integer", nullable: true),
                    DefaultEnableDetailedErrors = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultLogSensitiveData = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultThemeName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    RealmLogoUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RealmUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RealmPolicyUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RealmTosUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RealmCustomCssUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    AudienceMode = table.Column<int>(type: "integer", nullable: true),
                    PrimaryAudience = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IncludeAudInIdToken = table.Column<bool>(type: "boolean", nullable: true),
                    RequireExplicitAudienceScope = table.Column<bool>(type: "boolean", nullable: true),
                    DefaultJarMode = table.Column<int>(type: "integer", nullable: true),
                    DefaultJarmMode = table.Column<int>(type: "integer", nullable: true),
                    DefaultRequireSignedRequestObject = table.Column<bool>(type: "boolean", nullable: true),
                    DefaultAllowedRequestObjectAlgs = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Realms", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ReturnUrlEntries",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Url = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ReturnUrlEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Scopes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsRequired = table.Column<bool>(type: "boolean", nullable: false),
                    ShowInDiscoveryDocument = table.Column<bool>(type: "boolean", nullable: false),
                    IsStandard = table.Column<bool>(type: "boolean", nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Scopes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SecurityAuditEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    TimestampUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Category = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    EventType = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: false),
                    Level = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    ActorUserId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ActorClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    DataJson = table.Column<string>(type: "text", nullable: true),
                    PrevHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Hash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityAuditEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TokenStatisticsSnapshots",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Granularity = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    PeriodStartUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PeriodEndUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    AccessTokensIssued = table.Column<long>(type: "bigint", nullable: false),
                    RefreshTokensIssued = table.Column<long>(type: "bigint", nullable: false),
                    AuthorizationCodesIssued = table.Column<long>(type: "bigint", nullable: false),
                    DeviceCodesIssued = table.Column<long>(type: "bigint", nullable: false),
                    ActiveAccessTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    ActiveRefreshTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    ExpiredTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    RevokedTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TokenStatisticsSnapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserProfiles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "text", nullable: false),
                    FirstName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    LastName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    DisplayName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    State = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserProfiles", x => x.UserId);
                });

            migrationBuilder.CreateTable(
                name: "ApiResourceClaims",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ApiResourceId = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiResourceClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApiResourceClaims_ApiResources_ApiResourceId",
                        column: x => x.ApiResourceId,
                        principalTable: "ApiResources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ApiResourceScopes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ApiResourceId = table.Column<string>(type: "text", nullable: false),
                    Scope = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiResourceScopes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApiResourceScopes_ApiResources_ApiResourceId",
                        column: x => x.ApiResourceId,
                        principalTable: "ApiResources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ApiResourceSecrets",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ApiResourceId = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Value = table.Column<string>(type: "text", nullable: false),
                    Expiration = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Type = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiResourceSecrets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApiResourceSecrets_ApiResources_ApiResourceId",
                        column: x => x.ApiResourceId,
                        principalTable: "ApiResources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoleClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    RoleId = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "text", nullable: true),
                    ClaimValue = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserClaims",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "text", nullable: true),
                    ClaimValue = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserLogins",
                columns: table => new
                {
                    LoginProvider = table.Column<string>(type: "text", nullable: false),
                    ProviderKey = table.Column<string>(type: "text", nullable: false),
                    ProviderDisplayName = table.Column<string>(type: "text", nullable: true),
                    UserId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                    table.ForeignKey(
                        name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "text", nullable: false),
                    RoleId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserTokens",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "text", nullable: false),
                    LoginProvider = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Value = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                    table.ForeignKey(
                        name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserDevices",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    DeviceId = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    DeviceName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    DeviceType = table.Column<int>(type: "integer", nullable: false),
                    OperatingSystem = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IsTrusted = table.Column<bool>(type: "boolean", nullable: false),
                    CanApproveLogins = table.Column<bool>(type: "boolean", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    PushToken = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    PublicKey = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastIpAddress = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    LastLocation = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Metadata = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserDevices", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserDevices_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    CredentialId = table.Column<string>(type: "text", nullable: false),
                    PublicKey = table.Column<string>(type: "text", nullable: false),
                    UserHandle = table.Column<string>(type: "text", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    AaGuid = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    AttestationFmt = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    IsDiscoverable = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Nickname = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "IdentityResourceClaims",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    IdentityResourceId = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IdentityResourceClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IdentityResourceClaims_IdentityResources_IdentityResourceId",
                        column: x => x.IdentityResourceId,
                        principalTable: "IdentityResources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "IdentityResourceProperties",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    IdentityResourceId = table.Column<string>(type: "text", nullable: false),
                    Key = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                    Value = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IdentityResourceProperties", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IdentityResourceProperties_IdentityResources_IdentityResour~",
                        column: x => x.IdentityResourceId,
                        principalTable: "IdentityResources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "OpenIddictAuthorizations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ApplicationId = table.Column<string>(type: "text", nullable: true),
                    ConcurrencyToken = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    CreationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Properties = table.Column<string>(type: "text", nullable: true),
                    Scopes = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Subject = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                    Type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OpenIddictAuthorizations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OpenIddictAuthorizations_OpenIddictApplications_Application~",
                        column: x => x.ApplicationId,
                        principalTable: "OpenIddictApplications",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "Clients",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ClientSecret = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    ClientType = table.Column<int>(type: "integer", nullable: false),
                    AllowAuthorizationCodeFlow = table.Column<bool>(type: "boolean", nullable: false),
                    AllowClientCredentialsFlow = table.Column<bool>(type: "boolean", nullable: false),
                    AllowPasswordFlow = table.Column<bool>(type: "boolean", nullable: false),
                    AllowRefreshTokenFlow = table.Column<bool>(type: "boolean", nullable: false),
                    AllowDeviceCodeFlow = table.Column<bool>(type: "boolean", nullable: false),
                    RequirePkce = table.Column<bool>(type: "boolean", nullable: false),
                    RequireClientSecret = table.Column<bool>(type: "boolean", nullable: false),
                    ParMode = table.Column<int>(type: "integer", nullable: true),
                    AccessTokenLifetime = table.Column<double>(type: "double precision", nullable: true),
                    RefreshTokenLifetime = table.Column<double>(type: "double precision", nullable: true),
                    AuthorizationCodeLifetime = table.Column<double>(type: "double precision", nullable: true),
                    IdTokenLifetimeMinutes = table.Column<int>(type: "integer", nullable: true),
                    DeviceCodeLifetimeMinutes = table.Column<int>(type: "integer", nullable: true),
                    SessionTimeoutHours = table.Column<int>(type: "integer", nullable: true),
                    UseSlidingSessionExpiration = table.Column<bool>(type: "boolean", nullable: true),
                    RememberMeDurationDays = table.Column<int>(type: "integer", nullable: true),
                    RequireHttpsForCookies = table.Column<bool>(type: "boolean", nullable: true),
                    CookieSameSitePolicy = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    RequireConsent = table.Column<bool>(type: "boolean", nullable: true),
                    AllowRememberConsent = table.Column<bool>(type: "boolean", nullable: true),
                    MaxRefreshTokensPerUser = table.Column<int>(type: "integer", nullable: true),
                    UseOneTimeRefreshTokens = table.Column<bool>(type: "boolean", nullable: true),
                    IncludeJwtId = table.Column<bool>(type: "boolean", nullable: true),
                    AlwaysSendClientClaims = table.Column<bool>(type: "boolean", nullable: true),
                    AlwaysIncludeUserClaimsInIdToken = table.Column<bool>(type: "boolean", nullable: true),
                    UserCodeType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    DeviceCodePollingIntervalSeconds = table.Column<int>(type: "integer", nullable: true),
                    BackChannelLogoutSessionRequired = table.Column<bool>(type: "boolean", nullable: true),
                    BackChannelLogoutUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    FrontChannelLogoutSessionRequired = table.Column<bool>(type: "boolean", nullable: true),
                    FrontChannelLogoutUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    AccessTokenType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    HashAccessTokens = table.Column<bool>(type: "boolean", nullable: true),
                    UpdateAccessTokenClaimsOnRefresh = table.Column<bool>(type: "boolean", nullable: true),
                    AllowedCorsOrigins = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    ClientClaimsPrefix = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    PairWiseSubjectSalt = table.Column<bool>(type: "boolean", nullable: true),
                    RateLimitRequestsPerMinute = table.Column<int>(type: "integer", nullable: true),
                    RateLimitRequestsPerHour = table.Column<int>(type: "integer", nullable: true),
                    RateLimitRequestsPerDay = table.Column<int>(type: "integer", nullable: true),
                    AllowAccessToUserInfoEndpoint = table.Column<bool>(type: "boolean", nullable: true),
                    AllowAccessToIntrospectionEndpoint = table.Column<bool>(type: "boolean", nullable: true),
                    AllowAccessToRevocationEndpoint = table.Column<bool>(type: "boolean", nullable: true),
                    ProtocolType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    EnableLocalLogin = table.Column<bool>(type: "boolean", nullable: true),
                    AllowedIdentityProviders = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ShowClientLogo = table.Column<bool>(type: "boolean", nullable: true),
                    LogoUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ClientUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    PolicyUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    TosUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    EnableDetailedErrors = table.Column<bool>(type: "boolean", nullable: true),
                    LogSensitiveData = table.Column<bool>(type: "boolean", nullable: true),
                    CustomErrorPageUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    CustomLoginPageUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    CustomLogoutPageUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RequireMfa = table.Column<bool>(type: "boolean", nullable: true),
                    MfaGracePeriodMinutes = table.Column<int>(type: "integer", nullable: true),
                    AllowedMfaMethods = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    RememberMfaForSession = table.Column<bool>(type: "boolean", nullable: true),
                    CustomCssUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    CustomJavaScriptUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ThemeName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    PageTitlePrefix = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    AllowPasskeyLogin = table.Column<bool>(type: "boolean", nullable: true),
                    AllowQrLoginQuick = table.Column<bool>(type: "boolean", nullable: true),
                    AllowQrLoginSecure = table.Column<bool>(type: "boolean", nullable: true),
                    AllowCodeLogin = table.Column<bool>(type: "boolean", nullable: true),
                    JarRsaPublicKeyPem = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true),
                    RealmId = table.Column<string>(type: "text", nullable: false),
                    AudienceMode = table.Column<int>(type: "integer", nullable: true),
                    PrimaryAudience = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IncludeAudInIdToken = table.Column<bool>(type: "boolean", nullable: true),
                    RequireExplicitAudienceScope = table.Column<bool>(type: "boolean", nullable: true),
                    RoleInclusionOverride = table.Column<int>(type: "integer", nullable: true),
                    JarMode = table.Column<int>(type: "integer", nullable: true),
                    JarmMode = table.Column<int>(type: "integer", nullable: true),
                    RequireSignedRequestObject = table.Column<bool>(type: "boolean", nullable: true),
                    AllowedRequestObjectAlgs = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Clients", x => x.Id);
                    table.UniqueConstraint("AK_Clients_ClientId", x => x.ClientId);
                    table.ForeignKey(
                        name: "FK_Clients_Realms_RealmId",
                        column: x => x.RealmId,
                        principalTable: "Realms",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "IdentityProviders",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    RealmId = table.Column<string>(type: "text", nullable: true),
                    IconUri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Order = table.Column<int>(type: "integer", nullable: false),
                    Authority = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    MetadataAddress = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ClientSecret = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Scopes = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    ResponseType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    UsePkce = table.Column<bool>(type: "boolean", nullable: true),
                    GetClaimsFromUserInfoEndpoint = table.Column<bool>(type: "boolean", nullable: true),
                    ClaimMappingsJson = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    SamlEntityId = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    SamlSingleSignOnUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    SamlCertificate = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    SamlWantAssertionsSigned = table.Column<bool>(type: "boolean", nullable: true),
                    SamlValidateIssuer = table.Column<bool>(type: "boolean", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IdentityProviders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IdentityProviders_Realms_RealmId",
                        column: x => x.RealmId,
                        principalTable: "Realms",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "ScopeClaims",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ClaimType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ScopeId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScopeClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScopeClaims_Scopes_ScopeId",
                        column: x => x.ScopeId,
                        principalTable: "Scopes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeviceAuthenticationLogs",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    DeviceId = table.Column<string>(type: "text", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    ActivityType = table.Column<int>(type: "integer", nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IsSuccessful = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IpAddress = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    OccurredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Metadata = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceAuthenticationLogs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeviceAuthenticationLogs_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DeviceAuthenticationLogs_UserDevices_DeviceId",
                        column: x => x.DeviceId,
                        principalTable: "UserDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PersistentQrSessions",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Token = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: true),
                    ApprovedByDeviceId = table.Column<string>(type: "text", nullable: true),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ReturnUrl = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ApprovedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    InitiatorIpAddress = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ApproverIpAddress = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Metadata = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PersistentQrSessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PersistentQrSessions_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_PersistentQrSessions_UserDevices_ApprovedByDeviceId",
                        column: x => x.ApprovedByDeviceId,
                        principalTable: "UserDevices",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "OpenIddictTokens",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ApplicationId = table.Column<string>(type: "text", nullable: true),
                    AuthorizationId = table.Column<string>(type: "text", nullable: true),
                    ConcurrencyToken = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    CreationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExpirationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Payload = table.Column<string>(type: "text", nullable: true),
                    Properties = table.Column<string>(type: "text", nullable: true),
                    RedemptionDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ReferenceId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    Subject = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                    Type = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OpenIddictTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OpenIddictTokens_OpenIddictApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "OpenIddictApplications",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_OpenIddictTokens_OpenIddictAuthorizations_AuthorizationId",
                        column: x => x.AuthorizationId,
                        principalTable: "OpenIddictAuthorizations",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "ClientAudiences",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false),
                    Audience = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientAudiences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientAudiences_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientPermissions",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Permission = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientPermissions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientPermissions_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientPostLogoutUris",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientPostLogoutUris", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientPostLogoutUris_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientRedirectUris",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Uri = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientRedirectUris", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientRedirectUris_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientRoles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    NormalizedName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", nullable: false),
                    ConcurrencyStamp = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientRoles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientRoles_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "ClientId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientScopes",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Scope = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientScopes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientScopes_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientSecretHistories",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false),
                    SecretHash = table.Column<string>(type: "text", maxLength: 2000, nullable: false),
                    Algo = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    IsCompromised = table.Column<bool>(type: "boolean", nullable: false),
                    EncryptedSecret = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientSecretHistories", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientSecretHistories_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientUsers",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientUsers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientUsers_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ClientUsers_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientIdentityProviders",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    ClientId = table.Column<string>(type: "text", nullable: false),
                    IdentityProviderId = table.Column<string>(type: "text", nullable: false),
                    DisplayNameOverride = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: true),
                    Order = table.Column<int>(type: "integer", nullable: true),
                    OptionsJson = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    ClaimMappingsJson = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientIdentityProviders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ClientIdentityProviders_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ClientIdentityProviders_IdentityProviders_IdentityProviderId",
                        column: x => x.IdentityProviderId,
                        principalTable: "IdentityProviders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserClientRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "text", nullable: false),
                    ClientRoleId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserClientRoles", x => new { x.UserId, x.ClientRoleId });
                    table.ForeignKey(
                        name: "FK_UserClientRoles_ClientRoles_ClientRoleId",
                        column: x => x.ClientRoleId,
                        principalTable: "ClientRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ApiResourceClaims_ApiResourceId_ClaimType",
                table: "ApiResourceClaims",
                columns: new[] { "ApiResourceId", "ClaimType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiResources_Name",
                table: "ApiResources",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiResourceScopes_ApiResourceId_Scope",
                table: "ApiResourceScopes",
                columns: new[] { "ApiResourceId", "Scope" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiResourceSecrets_ApiResourceId",
                table: "ApiResourceSecrets",
                column: "ApiResourceId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClaims_RoleId",
                table: "AspNetRoleClaims",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserClaims_UserId",
                table: "AspNetUserClaims",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserLogins_UserId",
                table: "AspNetUserLogins",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_RoleId",
                table: "AspNetUserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditIntegrityRecords_Category",
                table: "AuditIntegrityRecords",
                column: "Category");

            migrationBuilder.CreateIndex(
                name: "IX_AuditIntegrityRecords_TimestampUtc",
                table: "AuditIntegrityRecords",
                column: "TimestampUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_EntityType_EntityId_OccurredAt",
                table: "AuditLogs",
                columns: new[] { "EntityType", "EntityId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_ClaimTypes_Type",
                table: "ClaimTypes",
                column: "Type",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientAudiences_ClientId_Audience",
                table: "ClientAudiences",
                columns: new[] { "ClientId", "Audience" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientIdentityProviders_ClientId_IdentityProviderId",
                table: "ClientIdentityProviders",
                columns: new[] { "ClientId", "IdentityProviderId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientIdentityProviders_IdentityProviderId",
                table: "ClientIdentityProviders",
                column: "IdentityProviderId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientPermissions_ClientId_Permission",
                table: "ClientPermissions",
                columns: new[] { "ClientId", "Permission" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientPostLogoutUris_ClientId_Uri",
                table: "ClientPostLogoutUris",
                columns: new[] { "ClientId", "Uri" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientRedirectUris_ClientId_Uri",
                table: "ClientRedirectUris",
                columns: new[] { "ClientId", "Uri" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientRoles_ClientId_NormalizedName",
                table: "ClientRoles",
                columns: new[] { "ClientId", "NormalizedName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Clients_ClientId",
                table: "Clients",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Clients_RealmId",
                table: "Clients",
                column: "RealmId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientScopes_ClientId_Scope",
                table: "ClientScopes",
                columns: new[] { "ClientId", "Scope" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientSecretHistories_ClientId_CreatedAt",
                table: "ClientSecretHistories",
                columns: new[] { "ClientId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_ClientSecretHistories_ClientId_Status",
                table: "ClientSecretHistories",
                columns: new[] { "ClientId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_ClientUsers_ClientId_UserId",
                table: "ClientUsers",
                columns: new[] { "ClientId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ClientUsers_UserId",
                table: "ClientUsers",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Consents_UserId_ClientId",
                table: "Consents",
                columns: new[] { "UserId", "ClientId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthenticationLogs_ActivityType_OccurredAt",
                table: "DeviceAuthenticationLogs",
                columns: new[] { "ActivityType", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthenticationLogs_ClientId_OccurredAt",
                table: "DeviceAuthenticationLogs",
                columns: new[] { "ClientId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthenticationLogs_DeviceId_OccurredAt",
                table: "DeviceAuthenticationLogs",
                columns: new[] { "DeviceId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthenticationLogs_UserId_OccurredAt",
                table: "DeviceAuthenticationLogs",
                columns: new[] { "UserId", "OccurredAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthorizations_ClientId_Status",
                table: "DeviceAuthorizations",
                columns: new[] { "ClientId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthorizations_DeviceCode",
                table: "DeviceAuthorizations",
                column: "DeviceCode",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthorizations_Status_ExpiresAt",
                table: "DeviceAuthorizations",
                columns: new[] { "Status", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceAuthorizations_UserCode",
                table: "DeviceAuthorizations",
                column: "UserCode");

            migrationBuilder.CreateIndex(
                name: "IX_IdentityProviders_RealmId_Name",
                table: "IdentityProviders",
                columns: new[] { "RealmId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IdentityResourceClaims_IdentityResourceId_ClaimType",
                table: "IdentityResourceClaims",
                columns: new[] { "IdentityResourceId", "ClaimType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IdentityResourceProperties_IdentityResourceId_Key",
                table: "IdentityResourceProperties",
                columns: new[] { "IdentityResourceId", "Key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IdentityResources_Name",
                table: "IdentityResources",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KeyMaterials_Kid",
                table: "KeyMaterials",
                column: "Kid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KeyMaterials_Use_IsPrimary",
                table: "KeyMaterials",
                columns: new[] { "Use", "IsPrimary" });

            migrationBuilder.CreateIndex(
                name: "IX_KeyMaterials_Use_Status_ActivateAt",
                table: "KeyMaterials",
                columns: new[] { "Use", "Status", "ActivateAt" });

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictApplications_ClientId",
                table: "OpenIddictApplications",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictAuthorizations_ApplicationId_Status_Subject_Type",
                table: "OpenIddictAuthorizations",
                columns: new[] { "ApplicationId", "Status", "Subject", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictScopes_Name",
                table: "OpenIddictScopes",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictTokens_ApplicationId_Status_Subject_Type",
                table: "OpenIddictTokens",
                columns: new[] { "ApplicationId", "Status", "Subject", "Type" });

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictTokens_AuthorizationId",
                table: "OpenIddictTokens",
                column: "AuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OpenIddictTokens_ReferenceId",
                table: "OpenIddictTokens",
                column: "ReferenceId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PendingClientRegistrations_Status_SubmittedAt",
                table: "PendingClientRegistrations",
                columns: new[] { "Status", "SubmittedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PersistentQrSessions_ApprovedByDeviceId",
                table: "PersistentQrSessions",
                column: "ApprovedByDeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_PersistentQrSessions_ClientId",
                table: "PersistentQrSessions",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_PersistentQrSessions_Status_ExpiresAt",
                table: "PersistentQrSessions",
                columns: new[] { "Status", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PersistentQrSessions_Token",
                table: "PersistentQrSessions",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PersistentQrSessions_UserId_Status",
                table: "PersistentQrSessions",
                columns: new[] { "UserId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_ClientId_ExpiresAt",
                table: "PushedAuthorizationRequests",
                columns: new[] { "ClientId", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_ExpiresAt",
                table: "PushedAuthorizationRequests",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_RequestUri",
                table: "PushedAuthorizationRequests",
                column: "RequestUri",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Realms_Name",
                table: "Realms",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ReturnUrlEntries_ExpiresAt",
                table: "ReturnUrlEntries",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_ScopeClaims_ScopeId_ClaimType",
                table: "ScopeClaims",
                columns: new[] { "ScopeId", "ClaimType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Scopes_Name",
                table: "Scopes",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityAuditEvents_TimestampUtc_Category",
                table: "SecurityAuditEvents",
                columns: new[] { "TimestampUtc", "Category" });

            migrationBuilder.CreateIndex(
                name: "IX_TokenStatisticsSnapshots_Granularity_PeriodStartUtc",
                table: "TokenStatisticsSnapshots",
                columns: new[] { "Granularity", "PeriodStartUtc" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserClientRoles_ClientRoleId_UserId",
                table: "UserClientRoles",
                columns: new[] { "ClientRoleId", "UserId" });

            migrationBuilder.CreateIndex(
                name: "IX_UserDevices_DeviceId",
                table: "UserDevices",
                column: "DeviceId");

            migrationBuilder.CreateIndex(
                name: "IX_UserDevices_UserId_DeviceId",
                table: "UserDevices",
                columns: new[] { "UserId", "DeviceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserDevices_UserId_IsActive",
                table: "UserDevices",
                columns: new[] { "UserId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_UserDevices_UserId_IsTrusted",
                table: "UserDevices",
                columns: new[] { "UserId", "IsTrusted" });

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_UserId_CredentialId",
                table: "WebAuthnCredentials",
                columns: new[] { "UserId", "CredentialId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ApiResourceClaims");

            migrationBuilder.DropTable(
                name: "ApiResourceScopes");

            migrationBuilder.DropTable(
                name: "ApiResourceSecrets");

            migrationBuilder.DropTable(
                name: "AspNetRoleClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserLogins");

            migrationBuilder.DropTable(
                name: "AspNetUserRoles");

            migrationBuilder.DropTable(
                name: "AspNetUserTokens");

            migrationBuilder.DropTable(
                name: "AuditIntegrityRecords");

            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "ClaimTypes");

            migrationBuilder.DropTable(
                name: "ClientAudiences");

            migrationBuilder.DropTable(
                name: "ClientIdentityProviders");

            migrationBuilder.DropTable(
                name: "ClientPermissions");

            migrationBuilder.DropTable(
                name: "ClientPostLogoutUris");

            migrationBuilder.DropTable(
                name: "ClientRedirectUris");

            migrationBuilder.DropTable(
                name: "ClientScopes");

            migrationBuilder.DropTable(
                name: "ClientSecretHistories");

            migrationBuilder.DropTable(
                name: "ClientUsers");

            migrationBuilder.DropTable(
                name: "Consents");

            migrationBuilder.DropTable(
                name: "DataProtectionKeys");

            migrationBuilder.DropTable(
                name: "DeviceAuthenticationLogs");

            migrationBuilder.DropTable(
                name: "DeviceAuthorizations");

            migrationBuilder.DropTable(
                name: "IdentityResourceClaims");

            migrationBuilder.DropTable(
                name: "IdentityResourceProperties");

            migrationBuilder.DropTable(
                name: "KeyMaterials");

            migrationBuilder.DropTable(
                name: "OpenIddictScopes");

            migrationBuilder.DropTable(
                name: "OpenIddictTokens");

            migrationBuilder.DropTable(
                name: "PendingClientRegistrations");

            migrationBuilder.DropTable(
                name: "PersistentQrSessions");

            migrationBuilder.DropTable(
                name: "PushedAuthorizationRequests");

            migrationBuilder.DropTable(
                name: "ReturnUrlEntries");

            migrationBuilder.DropTable(
                name: "ScopeClaims");

            migrationBuilder.DropTable(
                name: "SecurityAuditEvents");

            migrationBuilder.DropTable(
                name: "TokenStatisticsSnapshots");

            migrationBuilder.DropTable(
                name: "UserClientRoles");

            migrationBuilder.DropTable(
                name: "UserProfiles");

            migrationBuilder.DropTable(
                name: "WebAuthnCredentials");

            migrationBuilder.DropTable(
                name: "ApiResources");

            migrationBuilder.DropTable(
                name: "AspNetRoles");

            migrationBuilder.DropTable(
                name: "IdentityProviders");

            migrationBuilder.DropTable(
                name: "IdentityResources");

            migrationBuilder.DropTable(
                name: "OpenIddictAuthorizations");

            migrationBuilder.DropTable(
                name: "UserDevices");

            migrationBuilder.DropTable(
                name: "Scopes");

            migrationBuilder.DropTable(
                name: "ClientRoles");

            migrationBuilder.DropTable(
                name: "OpenIddictApplications");

            migrationBuilder.DropTable(
                name: "AspNetUsers");

            migrationBuilder.DropTable(
                name: "Clients");

            migrationBuilder.DropTable(
                name: "Realms");
        }
    }
}
