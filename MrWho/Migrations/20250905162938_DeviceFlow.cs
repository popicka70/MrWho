using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class DeviceFlow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllowDeviceCodeFlow",
                table: "Clients",
                type: "boolean",
                nullable: false,
                defaultValue: false);

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
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeviceAuthorizations");

            migrationBuilder.DropColumn(
                name: "AllowDeviceCodeFlow",
                table: "Clients");
        }
    }
}
