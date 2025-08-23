using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    public partial class AudienceConfig : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "AudienceMode",
                table: "Clients",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PrimaryAudience",
                table: "Clients",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IncludeAudInIdToken",
                table: "Clients",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequireExplicitAudienceScope",
                table: "Clients",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "AudienceMode",
                table: "Realms",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PrimaryAudience",
                table: "Realms",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IncludeAudInIdToken",
                table: "Realms",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "RequireExplicitAudienceScope",
                table: "Realms",
                type: "boolean",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "AudienceMode", table: "Clients");
            migrationBuilder.DropColumn(name: "PrimaryAudience", table: "Clients");
            migrationBuilder.DropColumn(name: "IncludeAudInIdToken", table: "Clients");
            migrationBuilder.DropColumn(name: "RequireExplicitAudienceScope", table: "Clients");
            migrationBuilder.DropColumn(name: "AudienceMode", table: "Realms");
            migrationBuilder.DropColumn(name: "PrimaryAudience", table: "Realms");
            migrationBuilder.DropColumn(name: "IncludeAudInIdToken", table: "Realms");
            migrationBuilder.DropColumn(name: "RequireExplicitAudienceScope", table: "Realms");
        }
    }
}
