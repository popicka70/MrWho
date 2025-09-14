using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class AddDeviceAutoLogin : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "DeviceAuthTokenExpiresAt",
                table: "UserDevices",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeviceAuthTokenHash",
                table: "UserDevices",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeviceAuthTokenSalt",
                table: "UserDevices",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DeviceAuthTokenExpiresAt",
                table: "UserDevices");

            migrationBuilder.DropColumn(
                name: "DeviceAuthTokenHash",
                table: "UserDevices");

            migrationBuilder.DropColumn(
                name: "DeviceAuthTokenSalt",
                table: "UserDevices");
        }
    }
}
