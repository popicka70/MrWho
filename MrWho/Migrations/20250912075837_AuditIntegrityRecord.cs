using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class AuditIntegrityRecord : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuditIntegrityRecords",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(26)", maxLength: 26, nullable: false),
                    TimestampUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Category = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Action = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: false),
                    ActorType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ActorId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    SubjectType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    SubjectId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    RealmId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    DataJson = table.Column<string>(type: "text", nullable: true),
                    PreviousHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    RecordHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditIntegrityRecords", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditIntegrityRecords_Category",
                table: "AuditIntegrityRecords",
                column: "Category");

            migrationBuilder.CreateIndex(
                name: "IX_AuditIntegrityRecords_TimestampUtc",
                table: "AuditIntegrityRecords",
                column: "TimestampUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditIntegrityRecords");
        }
    }
}
