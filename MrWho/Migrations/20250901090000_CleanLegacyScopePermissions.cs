using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MrWho.Data;

#nullable disable

namespace MrWho.Migrations
{
    /// <summary>
    /// Data cleanup migration removing legacy stored scope permissions from ClientPermissions.
    /// </summary>
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20250901090000_CleanLegacyScopePermissions")] // Explicit id so EF picks it up
    public partial class CleanLegacyScopePermissions : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Remove legacy oidc:scope:* permissions
            migrationBuilder.Sql("DELETE FROM \"ClientPermissions\" WHERE \"Permission\" LIKE 'oidc:scope:%';");

            // Remove old api.* permissions that were not namespaced correctly
            migrationBuilder.Sql("DELETE FROM \"ClientPermissions\" WHERE \"Permission\" LIKE 'api.%' AND \"Permission\" NOT LIKE 'scp:%';");

            // Remove stored scp:* permissions for standard/API scopes now derived dynamically
            migrationBuilder.Sql("DELETE FROM \"ClientPermissions\" WHERE \"Permission\" IN ('scp:openid','scp:email','scp:profile','scp:roles','scp:offline_access','scp:api.read','scp:api.write');");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // No-op (data cleanup not reversible)
        }
    }
}
