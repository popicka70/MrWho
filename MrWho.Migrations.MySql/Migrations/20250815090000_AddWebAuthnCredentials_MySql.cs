using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddWebAuthnCredentials_MySql : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserId = table.Column<string>(type: "longtext", nullable: false),
                    CredentialId = table.Column<string>(type: "longtext", nullable: false),
                    PublicKey = table.Column<string>(type: "longtext", nullable: false),
                    UserHandle = table.Column<string>(type: "longtext", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    AaGuid = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    AttestationFmt = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    IsDiscoverable = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    Nickname = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnCredentials", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_WebAuthnCredentials_UserId_CredentialId",
                table: "WebAuthnCredentials",
                columns: new[] { "UserId", "CredentialId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "WebAuthnCredentials");
        }
    }
}
