using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace MrWho.Migrations.MySql.Migrations
{
    [DbContext(typeof(MrWho.Data.ApplicationDbContext))]
    [Migration("20250814090510_AddUserProfileAndUserState_MySql")]
    partial class AddUserProfileAndUserState_MySql
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
            // Minimal stub
        }
    }
}
