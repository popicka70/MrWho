using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class LoginOptions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllowCodeLogin",
                table: "Clients",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowPasskeyLogin",
                table: "Clients",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowQrLoginQuick",
                table: "Clients",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "AllowQrLoginSecure",
                table: "Clients",
                type: "boolean",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowCodeLogin",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowPasskeyLogin",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowQrLoginQuick",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "AllowQrLoginSecure",
                table: "Clients");
        }
    }
}
