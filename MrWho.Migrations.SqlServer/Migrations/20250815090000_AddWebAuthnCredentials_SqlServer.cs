using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddWebAuthnCredentials_SqlServer : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "WebAuthnCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    CredentialId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    PublicKey = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserHandle = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    AaGuid = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    AttestationFmt = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    IsDiscoverable = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Nickname = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true)
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
