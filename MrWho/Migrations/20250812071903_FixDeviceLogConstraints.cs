using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class FixDeviceLogConstraints : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_DeviceAuthenticationLogs_AspNetUsers_UserId",
                table: "DeviceAuthenticationLogs");

            migrationBuilder.DropForeignKey(
                name: "FK_DeviceAuthenticationLogs_UserDevices_DeviceId",
                table: "DeviceAuthenticationLogs");

            migrationBuilder.AddForeignKey(
                name: "FK_DeviceAuthenticationLogs_AspNetUsers_UserId",
                table: "DeviceAuthenticationLogs",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_DeviceAuthenticationLogs_UserDevices_DeviceId",
                table: "DeviceAuthenticationLogs",
                column: "DeviceId",
                principalTable: "UserDevices",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_DeviceAuthenticationLogs_AspNetUsers_UserId",
                table: "DeviceAuthenticationLogs");

            migrationBuilder.DropForeignKey(
                name: "FK_DeviceAuthenticationLogs_UserDevices_DeviceId",
                table: "DeviceAuthenticationLogs");

            migrationBuilder.AddForeignKey(
                name: "FK_DeviceAuthenticationLogs_AspNetUsers_UserId",
                table: "DeviceAuthenticationLogs",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_DeviceAuthenticationLogs_UserDevices_DeviceId",
                table: "DeviceAuthenticationLogs",
                column: "DeviceId",
                principalTable: "UserDevices",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
