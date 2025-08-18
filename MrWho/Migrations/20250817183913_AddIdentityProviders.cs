using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class AddIdentityProviders : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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
                name: "IX_IdentityProviders_RealmId_Name",
                table: "IdentityProviders",
                columns: new[] { "RealmId", "Name" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClientIdentityProviders");

            migrationBuilder.DropTable(
                name: "IdentityProviders");
        }
    }
}
