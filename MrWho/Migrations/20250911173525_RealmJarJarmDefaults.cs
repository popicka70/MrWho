using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace MrWho.Migrations
{
    /// <inheritdoc />
    public partial class RealmJarJarmDefaults : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Guard: only add Realm columns if they don't already exist
            migrationBuilder.Sql(@"DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultJarMode') THEN
                    ALTER TABLE ""Realms"" ADD COLUMN ""DefaultJarMode"" integer NULL;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultJarmMode') THEN
                    ALTER TABLE ""Realms"" ADD COLUMN ""DefaultJarmMode"" integer NULL;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultRequireSignedRequestObject') THEN
                    ALTER TABLE ""Realms"" ADD COLUMN ""DefaultRequireSignedRequestObject"" boolean NULL;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultAllowedRequestObjectAlgs') THEN
                    ALTER TABLE ""Realms"" ADD COLUMN ""DefaultAllowedRequestObjectAlgs"" character varying(400) NULL;
                END IF;
            END $$;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Guarded drops (only if exist)
            migrationBuilder.Sql(@"DO $$ BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultJarMode') THEN
                    ALTER TABLE ""Realms"" DROP COLUMN ""DefaultJarMode"";
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultJarmMode') THEN
                    ALTER TABLE ""Realms"" DROP COLUMN ""DefaultJarmMode"";
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultRequireSignedRequestObject') THEN
                    ALTER TABLE ""Realms"" DROP COLUMN ""DefaultRequireSignedRequestObject"";
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='Realms' AND column_name='DefaultAllowedRequestObjectAlgs') THEN
                    ALTER TABLE ""Realms"" DROP COLUMN ""DefaultAllowedRequestObjectAlgs"";
                END IF;
            END $$;");
        }
    }
}
