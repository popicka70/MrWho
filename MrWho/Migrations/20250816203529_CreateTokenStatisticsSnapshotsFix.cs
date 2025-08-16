using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class CreateTokenStatisticsSnapshotsFix : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Create the table if it doesn't exist (works when earlier migration was empty)
            migrationBuilder.CreateTable(
                name: "TokenStatisticsSnapshots",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Granularity = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    PeriodStartUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PeriodEndUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    AccessTokensIssued = table.Column<long>(type: "bigint", nullable: false),
                    RefreshTokensIssued = table.Column<long>(type: "bigint", nullable: false),
                    AuthorizationCodesIssued = table.Column<long>(type: "bigint", nullable: false),
                    DeviceCodesIssued = table.Column<long>(type: "bigint", nullable: false),
                    ActiveAccessTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    ActiveRefreshTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    ExpiredTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    RevokedTokensEnd = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TokenStatisticsSnapshots", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TokenStatisticsSnapshots_Granularity_PeriodStartUtc",
                table: "TokenStatisticsSnapshots",
                columns: new[] { "Granularity", "PeriodStartUtc" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TokenStatisticsSnapshots");
        }
    }
}
