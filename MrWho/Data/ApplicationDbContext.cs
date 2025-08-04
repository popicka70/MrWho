using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MrWho.Models;

namespace MrWho.Data;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Realm and Client management entities
    public DbSet<Realm> Realms { get; set; }
    public DbSet<Client> Clients { get; set; }
    public DbSet<ClientRedirectUri> ClientRedirectUris { get; set; }
    public DbSet<ClientPostLogoutUri> ClientPostLogoutUris { get; set; }
    public DbSet<ClientScope> ClientScopes { get; set; }
    public DbSet<ClientPermission> ClientPermissions { get; set; }
    
    // Scope management entities
    public DbSet<Scope> Scopes { get; set; }
    public DbSet<ScopeClaim> ScopeClaims { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict();

        // Configure Realm entity
        builder.Entity<Realm>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.HasIndex(r => r.Name).IsUnique();
            entity.Property(r => r.AccessTokenLifetime).HasConversion(
                v => v.TotalMinutes,
                v => TimeSpan.FromMinutes(v));
            entity.Property(r => r.RefreshTokenLifetime).HasConversion(
                v => v.TotalMinutes,
                v => TimeSpan.FromMinutes(v));
            entity.Property(r => r.AuthorizationCodeLifetime).HasConversion(
                v => v.TotalMinutes,
                v => TimeSpan.FromMinutes(v));
        });

        // Configure Client entity
        builder.Entity<Client>(entity =>
        {
            entity.HasKey(c => c.Id);
            entity.HasIndex(c => c.ClientId).IsUnique();
            entity.HasOne(c => c.Realm)
                  .WithMany(r => r.Clients)
                  .HasForeignKey(c => c.RealmId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.Property(c => c.AccessTokenLifetime).HasConversion(
                v => v.HasValue ? v.Value.TotalMinutes : (double?)null,
                v => v.HasValue ? TimeSpan.FromMinutes(v.Value) : null);
            entity.Property(c => c.RefreshTokenLifetime).HasConversion(
                v => v.HasValue ? v.Value.TotalMinutes : (double?)null,
                v => v.HasValue ? TimeSpan.FromMinutes(v.Value) : null);
            entity.Property(c => c.AuthorizationCodeLifetime).HasConversion(
                v => v.HasValue ? v.Value.TotalMinutes : (double?)null,
                v => v.HasValue ? TimeSpan.FromMinutes(v.Value) : null);
        });

        // Configure ClientRedirectUri entity
        builder.Entity<ClientRedirectUri>(entity =>
        {
            entity.HasKey(ru => ru.Id);
            entity.HasOne(ru => ru.Client)
                  .WithMany(c => c.RedirectUris)
                  .HasForeignKey(ru => ru.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(ru => new { ru.ClientId, ru.Uri }).IsUnique();
        });

        // Configure ClientPostLogoutUri entity
        builder.Entity<ClientPostLogoutUri>(entity =>
        {
            entity.HasKey(plu => plu.Id);
            entity.HasOne(plu => plu.Client)
                  .WithMany(c => c.PostLogoutUris)
                  .HasForeignKey(plu => plu.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(plu => new { plu.ClientId, plu.Uri }).IsUnique();
        });

        // Configure ClientScope entity
        builder.Entity<ClientScope>(entity =>
        {
            entity.HasKey(cs => cs.Id);
            entity.HasOne(cs => cs.Client)
                  .WithMany(c => c.Scopes)
                  .HasForeignKey(cs => cs.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(cs => new { cs.ClientId, cs.Scope }).IsUnique();
        });

        // Configure ClientPermission entity
        builder.Entity<ClientPermission>(entity =>
        {
            entity.HasKey(cp => cp.Id);
            entity.HasOne(cp => cp.Client)
                  .WithMany(c => c.Permissions)
                  .HasForeignKey(cp => cp.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(cp => new { cp.ClientId, cp.Permission }).IsUnique();
        });
        
        // Configure Scope entity
        builder.Entity<Scope>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.HasIndex(s => s.Name).IsUnique();
        });

        // Configure ScopeClaim entity
        builder.Entity<ScopeClaim>(entity =>
        {
            entity.HasKey(sc => sc.Id);
            entity.HasOne(sc => sc.Scope)
                  .WithMany(s => s.Claims)
                  .HasForeignKey(sc => sc.ScopeId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(sc => new { sc.ScopeId, sc.ClaimType }).IsUnique();
        });
    }
}