using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class PushedAuthorizationRequest : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PushedAuthorizationRequests",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    RequestUri = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ParametersJson = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ConsumedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ParametersHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PushedAuthorizationRequests", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_ClientId_ExpiresAt",
                table: "PushedAuthorizationRequests",
                columns: new[] { "ClientId", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_ExpiresAt",
                table: "PushedAuthorizationRequests",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_RequestUri",
                table: "PushedAuthorizationRequests",
                column: "RequestUri",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PushedAuthorizationRequests");
        }
    }
}
