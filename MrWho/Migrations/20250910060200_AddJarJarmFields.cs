using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class AddJarJarmFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "JarMode",
                table: "Clients",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "JarmMode",
                table: "Clients",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequireSignedRequestObject",
                table: "Clients",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AllowedRequestObjectAlgs",
                table: "Clients",
                type: "character varying(400)",
                maxLength: 400,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "JarMode",
                table: "Clients");
            migrationBuilder.DropColumn(
                name: "JarmMode",
                table: "Clients");
            migrationBuilder.DropColumn(
                name: "RequireSignedRequestObject",
                table: "Clients");
            migrationBuilder.DropColumn(
                name: "AllowedRequestObjectAlgs",
                table: "Clients");
        }
    }
}
