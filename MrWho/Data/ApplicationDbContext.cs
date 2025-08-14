using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using MrWho.Models;

namespace MrWho.Data;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>, IDataProtectionKeyContext
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
    public DbSet<ClientUser> ClientUsers { get; set; }
    
    // Scope management entities
    public DbSet<Scope> Scopes { get; set; }
    public DbSet<ScopeClaim> ScopeClaims { get; set; }
    
    // API Resource management entities
    public DbSet<ApiResource> ApiResources { get; set; }
    public DbSet<ApiResourceScope> ApiResourceScopes { get; set; }
    public DbSet<ApiResourceClaim> ApiResourceClaims { get; set; }
    public DbSet<ApiResourceSecret> ApiResourceSecrets { get; set; }

    // Identity Resource management entities
    public DbSet<IdentityResource> IdentityResources { get; set; }
    public DbSet<IdentityResourceClaim> IdentityResourceClaims { get; set; }
    public DbSet<IdentityResourceProperty> IdentityResourceProperties { get; set; }

    // Device management entities
    public DbSet<UserDevice> UserDevices { get; set; }
    public DbSet<PersistentQrSession> PersistentQrSessions { get; set; }
    public DbSet<DeviceAuthenticationLog> DeviceAuthenticationLogs { get; set; }

    // User profile
    public DbSet<UserProfile> UserProfiles { get; set; }

    // Data Protection keys for antiforgery/auth cookie encryption persistence
    public DbSet<Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey> DataProtectionKeys { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict();

        // Configure UserProfile entity
        builder.Entity<UserProfile>(entity =>
        {
            entity.HasKey(p => p.UserId);
            entity.Property(p => p.FirstName).HasMaxLength(256);
            entity.Property(p => p.LastName).HasMaxLength(256);
            entity.Property(p => p.DisplayName).HasMaxLength(512);
        });

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

        // Configure ClientUser entity (user-client assignments)
        builder.Entity<ClientUser>(entity =>
        {
            entity.HasKey(cu => cu.Id);
            entity.HasIndex(cu => new { cu.ClientId, cu.UserId }).IsUnique();
            entity.HasOne(cu => cu.Client)
                  .WithMany()
                  .HasForeignKey(cu => cu.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(cu => cu.User)
                  .WithMany()
                  .HasForeignKey(cu => cu.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure Identity Resource entities
        builder.Entity<IdentityResource>(entity =>
        {
            entity.HasKey(ir => ir.Id);
            entity.HasIndex(ir => ir.Name).IsUnique();
        });

        builder.Entity<IdentityResourceClaim>(entity =>
        {
            entity.HasKey(irc => irc.Id);
            entity.HasOne(irc => irc.IdentityResource)
                  .WithMany(ir => ir.UserClaims)
                  .HasForeignKey(irc => irc.IdentityResourceId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(irc => new { irc.IdentityResourceId, irc.ClaimType }).IsUnique();
        });

        builder.Entity<IdentityResourceProperty>(entity =>
        {
            entity.HasKey(irp => irp.Id);
            entity.HasOne(irp => irp.IdentityResource)
                  .WithMany(ir => ir.Properties)
                  .HasForeignKey(irp => irp.IdentityResourceId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(irp => new { irp.IdentityResourceId, irp.Key }).IsUnique();
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
        
        // Configure ApiResource entity
        builder.Entity<ApiResource>(entity =>
        {
            entity.HasKey(ar => ar.Id);
            entity.HasIndex(ar => ar.Name).IsUnique();
        });

        // Configure ApiResourceScope entity
        builder.Entity<ApiResourceScope>(entity =>
        {
            entity.HasKey(ars => ars.Id);
            entity.HasOne(ars => ars.ApiResource)
                  .WithMany(ar => ar.Scopes)
                  .HasForeignKey(ars => ars.ApiResourceId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(ars => new { ars.ApiResourceId, ars.Scope }).IsUnique();
        });

        // Configure ApiResourceClaim entity
        builder.Entity<ApiResourceClaim>(entity =>
        {
            entity.HasKey(arc => arc.Id);
            entity.HasOne(arc => arc.ApiResource)
                  .WithMany(ar => ar.UserClaims)
                  .HasForeignKey(arc => arc.ApiResourceId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(arc => new { arc.ApiResourceId, arc.ClaimType }).IsUnique();
        });

        // Configure ApiResourceSecret entity
        builder.Entity<ApiResourceSecret>(entity =>
        {
            entity.HasKey(ars => ars.Id);
            entity.HasOne(ars => ars.ApiResource)
                  .WithMany(ar => ar.Secrets)
                  .HasForeignKey(ars => ars.ApiResourceId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // =========================================================================
        // DEVICE MANAGEMENT CONFIGURATION
        // ============================================================================

        // Configure UserDevice entity
        builder.Entity<UserDevice>(entity =>
        {
            entity.HasKey(d => d.Id);
            entity.HasIndex(d => d.DeviceId);
            entity.HasIndex(d => new { d.UserId, d.DeviceId }).IsUnique();
            entity.HasIndex(d => new { d.UserId, d.IsActive });
            entity.HasIndex(d => new { d.UserId, d.IsTrusted });
            
            entity.HasOne(d => d.User)
                  .WithMany()
                  .HasForeignKey(d => d.UserId)
                  .OnDelete(DeleteBehavior.Restrict); // Changed from Cascade to Restrict - no hard deletes anyway
        });

        // Configure PersistentQrSession entity
        builder.Entity<PersistentQrSession>(entity =>
        {
            entity.HasKey(q => q.Id);
            entity.HasIndex(q => q.Token).IsUnique();
            entity.HasIndex(q => new { q.UserId, q.Status });
            entity.HasIndex(q => new { q.Status, q.ExpiresAt });
            entity.HasIndex(q => q.ClientId);
            
            entity.HasOne(q => q.User)
                  .WithMany()
                  .HasForeignKey(q => q.UserId)
                  .OnDelete(DeleteBehavior.SetNull); // SetNull is fine since UserId is nullable
                  
            entity.HasOne(q => q.ApprovedByDevice)
                  .WithMany(d => d.QrSessions)
                  .HasForeignKey(q => q.ApprovedByDeviceId)
                  .OnDelete(DeleteBehavior.SetNull); // SetNull is fine since ApprovedByDeviceId is nullable
        });

        // Configure DeviceAuthenticationLog entity
        builder.Entity<DeviceAuthenticationLog>(entity =>
        {
            entity.HasKey(l => l.Id);
            entity.HasIndex(l => new { l.DeviceId, l.OccurredAt });
            entity.HasIndex(l => new { l.UserId, l.OccurredAt });
            entity.HasIndex(l => new { l.ActivityType, l.OccurredAt });
            entity.HasIndex(l => new { l.ClientId, l.OccurredAt });
            
            entity.HasOne(l => l.Device)
                  .WithMany(d => d.AuthenticationLogs)
                  .HasForeignKey(l => l.DeviceId)
                  .OnDelete(DeleteBehavior.Restrict); // No cascade - logs are audit data, keep them
                  
            entity.HasOne(l => l.User)
                  .WithMany()
                  .HasForeignKey(l => l.UserId)
                  .OnDelete(DeleteBehavior.Restrict); // No cascade - logs are audit data, keep them
        });

        // Configure DataProtectionKey entity
        builder.Entity<Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey>(entity =>
        {
            entity.HasKey(k => k.Id);
            entity.Property(k => k.FriendlyName).HasMaxLength(256);
        });
    }
}