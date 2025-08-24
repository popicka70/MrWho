using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class ClientScopedRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "AK_Clients_ClientId",
                table: "Clients",
                column: "ClientId");

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
                name: "IX_ClientRoles_ClientId_NormalizedName",
                table: "ClientRoles",
                columns: new[] { "ClientId", "NormalizedName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserClientRoles_ClientRoleId_UserId",
                table: "UserClientRoles",
                columns: new[] { "ClientRoleId", "UserId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserClientRoles");

            migrationBuilder.DropTable(
                name: "ClientRoles");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_Clients_ClientId",
                table: "Clients");
        }
    }
}
