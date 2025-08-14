using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MrWho.Migrations.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AddUserProfileAndUserState : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder.ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
            {
                migrationBuilder.Sql(@"
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[UserProfiles]') AND type in (N'U'))
BEGIN
    CREATE TABLE [dbo].[UserProfiles](
        [UserId] nvarchar(450) NOT NULL,
        [FirstName] nvarchar(256) NULL,
        [LastName] nvarchar(256) NULL,
        [DisplayName] nvarchar(512) NULL,
        [State] int NOT NULL,
        [CreatedAt] datetime2 NOT NULL,
        [UpdatedAt] datetime2 NULL,
        CONSTRAINT [PK_UserProfiles] PRIMARY KEY ([UserId])
    );
END
");
            }
            else
            {
                // Fallback for any other providers using default EF generation
                migrationBuilder.CreateTable(
                    name: "UserProfiles",
                    columns: table => new
                    {
                        UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                        FirstName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                        LastName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                        DisplayName = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                        State = table.Column<int>(type: "int", nullable: false),
                        CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                        UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                    },
                    constraints: table =>
                    {
                        table.PrimaryKey("PK_UserProfiles", x => x.UserId);
                    });
            }
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder.ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
            {
                migrationBuilder.Sql(@"
IF OBJECT_ID(N'[dbo].[UserProfiles]', 'U') IS NOT NULL
BEGIN
    DROP TABLE [dbo].[UserProfiles];
END
");
            }
            else
            {
                migrationBuilder.DropTable(
                    name: "UserProfiles");
            }
        }
    }
}
