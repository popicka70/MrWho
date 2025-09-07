using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class KeyManagement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "KeyMaterials");
        }
    }
}
