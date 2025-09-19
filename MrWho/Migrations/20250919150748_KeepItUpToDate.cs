using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class KeepItUpToDate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_PushedAuthorizationRequests_ClientId_ParametersHash",
                table: "PushedAuthorizationRequests",
                columns: new[] { "ClientId", "ParametersHash" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PushedAuthorizationRequests_ClientId_ParametersHash",
                table: "PushedAuthorizationRequests");
        }
    }
}
