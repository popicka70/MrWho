using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace MrWho.Migrations.PostgreSql.Migrations
{
    [DbContext(typeof(MrWho.Data.ApplicationDbContext))]
    [Migration("20250814090500_AddUserProfileAndUserState_Pg")]
    partial class AddUserProfileAndUserState_Pg
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
            // intentionally minimal; runtime uses the main DbContext model
        }
    }
}
