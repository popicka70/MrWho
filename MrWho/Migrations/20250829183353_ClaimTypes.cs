using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class ClaimTypes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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

            migrationBuilder.CreateIndex(
                name: "IX_ClaimTypes_Type",
                table: "ClaimTypes",
                column: "Type",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClaimTypes");
        }
    }
}
