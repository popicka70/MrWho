using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class AddPendingClientRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PendingClientRegistrations",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    SubmittedByUserId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    SubmittedByUserName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    SubmittedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    ReviewedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ReviewedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ReviewReason = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    ClientName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    TokenEndpointAuthMethod = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    Scope = table.Column<string>(type: "text", maxLength: 2000, nullable: true),
                    RedirectUrisCsv = table.Column<string>(type: "text", maxLength: 4000, nullable: true),
                    RawRequestJson = table.Column<string>(type: "text", nullable: false),
                    CreatedClientDbId = table.Column<string>(type: "text", nullable: true),
                    CreatedClientPublicId = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PendingClientRegistrations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PendingClientRegistrations_Status_SubmittedAt",
                table: "PendingClientRegistrations",
                columns: new[] { "Status", "SubmittedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PendingClientRegistrations");
        }
    }
}
