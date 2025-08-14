using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace MrWho.Migrations.SqlServer.Migrations
{
    [DbContext(typeof(MrWho.Data.ApplicationDbContext))]
    [Migration("20250814090520_AddUserProfileAndUserState")]
    partial class AddUserProfileAndUserState
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
            // Minimal stub
        }
    }
}
