using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddWebAuthnCredentials_PostgreSql : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<string>(type: "text", nullable: false),
                    CredentialId = table.Column<string>(type: "text", nullable: false),
                    PublicKey = table.Column<string>(type: "text", nullable: false),
                    UserHandle = table.Column<string>(type: "text", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    AaGuid = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    AttestationFmt = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    IsDiscoverable = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Nickname = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebAuthnCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_WebAuthnCredentials_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

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
