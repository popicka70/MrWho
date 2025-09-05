using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using MrWho.Models;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace MrWho.Data;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>, IDataProtectionKeyContext
{
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IHttpContextAccessor? httpContextAccessor = null)
        : base(options)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    // Realm and Client management entities
    public DbSet<Realm> Realms { get; set; }
    public DbSet<Client> Clients { get; set; }
    public DbSet<ClientRedirectUri> ClientRedirectUris { get; set; }
    public DbSet<ClientPostLogoutUri> ClientPostLogoutUris { get; set; }
    public DbSet<ClientScope> ClientScopes { get; set; }
    public DbSet<ClientPermission> ClientPermissions { get; set; }
    public DbSet<ClientUser> ClientUsers { get; set; }
    
    // NEW: Identity brokering entities
    public DbSet<IdentityProvider> IdentityProviders { get; set; }
    public DbSet<ClientIdentityProvider> ClientIdentityProviders { get; set; }
    
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
    public DbSet<DeviceAuthorization> DeviceAuthorizations { get; set; }

    // Audit logging
    public DbSet<AuditLog> AuditLogs { get; set; }

    // User profile
    public DbSet<UserProfile> UserProfiles { get; set; }

    // WebAuthn credentials
    public DbSet<WebAuthnCredential> WebAuthnCredentials { get; set; }

    // Statistics snapshots
    public DbSet<TokenStatisticsSnapshot> TokenStatisticsSnapshots { get; set; }

    // Data Protection keys for antiforgery/auth cookie encryption persistence
    public DbSet<Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey> DataProtectionKeys { get; set; }

    // NEW: Client audiences
    public DbSet<ClientAudience> ClientAudiences { get; set; }

    // NEW: Client scoped roles
    public DbSet<ClientRole> ClientRoles { get; set; } = null!;
    public DbSet<UserClientRole> UserClientRoles { get; set; } = null!;

    // NEW: Claim types registry
    public DbSet<ClaimType> ClaimTypes { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.UseOpenIddict();

        // Configure ClientRole entity
        builder.Entity<ClientRole>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.Property(r => r.Name).HasMaxLength(256).IsRequired();
            entity.Property(r => r.NormalizedName).HasMaxLength(256).IsRequired();
            entity.Property(r => r.ClientId).IsRequired();
            entity.HasIndex(r => new { r.ClientId, r.NormalizedName }).IsUnique();
            entity.HasOne(r => r.Client)
                  .WithMany(c => c.ClientRoles)
                  .HasForeignKey(r => r.ClientId)
                  .HasPrincipalKey(c => c.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<UserClientRole>(entity =>
        {
            entity.HasKey(ucr => new { ucr.UserId, ucr.ClientRoleId });
            entity.HasOne(ucr => ucr.ClientRole)
                  .WithMany(r => r.UserClientRoles)
                  .HasForeignKey(ucr => ucr.ClientRoleId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(ucr => new { ucr.ClientRoleId, ucr.UserId });
        });

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
            entity.HasAlternateKey(c => c.ClientId); // allow foreign keys to reference public ClientId
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

        // Configure IdentityProvider entity
        builder.Entity<IdentityProvider>(entity =>
        {
            entity.HasKey(ip => ip.Id);
            entity.HasIndex(ip => new { ip.RealmId, ip.Name }).IsUnique();
            entity.Property(ip => ip.ClaimMappingsJson).HasMaxLength(4000);
        });

        // Configure ClientIdentityProvider entity
        builder.Entity<ClientIdentityProvider>(entity =>
        {
            entity.HasKey(cip => cip.Id);
            entity.HasIndex(cip => new { cip.ClientId, cip.IdentityProviderId }).IsUnique();
            entity.HasOne(cip => cip.Client)
                  .WithMany(c => c.IdentityProviders)
                  .HasForeignKey(cip => cip.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(cip => cip.IdentityProvider)
                  .WithMany(ip => ip.ClientLinks)
                  .HasForeignKey(cip => cip.IdentityProviderId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.Property(cip => cip.ClaimMappingsJson).HasMaxLength(4000);
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
        // =================================================================

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

        // Configure DeviceAuthorization entity
        builder.Entity<DeviceAuthorization>(entity =>
        {
            entity.HasIndex(d => d.DeviceCode).IsUnique();
            entity.HasIndex(d => d.UserCode);
            entity.HasIndex(d => new { d.ClientId, d.Status });
            entity.HasIndex(d => new { d.Status, d.ExpiresAt });
        });

        // =========================================================================
        // AUDIT LOG CONFIGURATION
        // =========================================================================
        builder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(a => a.Id);
            entity.HasIndex(a => new { a.EntityType, a.EntityId, a.OccurredAt });
            // Do not impose a fixed max length here; provider-specific mapping below
        });

        // =========================================================================
        // WEBAUTHN CONFIGURATION
        // =========================================================================
        builder.Entity<WebAuthnCredential>(entity =>
        {
            entity.HasKey(c => c.Id);
            entity.HasIndex(c => new { c.UserId, c.CredentialId }).IsUnique();
            entity.Property(c => c.CredentialId).IsRequired();
            entity.Property(c => c.PublicKey).IsRequired();
            entity.Property(c => c.UserHandle).IsRequired();
            entity.Property(c => c.AaGuid).HasMaxLength(64);
            entity.Property(c => c.AttestationFmt).HasMaxLength(64);
            entity.Property(c => c.Nickname).HasMaxLength(256);

            entity.HasOne<IdentityUser>()
                  .WithMany()
                  .HasForeignKey(c => c.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure TokenStatisticsSnapshot entity
        builder.Entity<TokenStatisticsSnapshot>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.HasIndex(s => new { s.Granularity, s.PeriodStartUtc }).IsUnique();
        });

        // Configure DataProtectionKey entity
        builder.Entity<Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey>(entity =>
        {
            entity.HasKey(k => k.Id);
            entity.Property(k => k.FriendlyName).HasMaxLength(256);
        });

        // NEW: ClientAudience entity configuration
        builder.Entity<ClientAudience>(entity =>
        {
            entity.HasKey(a => a.Id);
            entity.HasOne(a => a.Client)
                  .WithMany(c => c.Audiences)
                  .HasForeignKey(a => a.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(a => new { a.ClientId, a.Audience }).IsUnique();
        });

        // ClaimType registry configuration
        builder.Entity<ClaimType>(entity =>
        {
            entity.HasKey(ct => ct.Id);
            entity.HasIndex(ct => ct.Type).IsUnique();
            entity.Property(ct => ct.Type).IsRequired();
        });

        // Provider-specific tuning: MySQL row size limits -> move large strings to longtext
        if (Database.ProviderName?.Contains("MySql", StringComparison.OrdinalIgnoreCase) == true)
        {
            builder.Entity<Client>(entity =>
            {
                entity.Property(c => c.AllowedCorsOrigins).HasColumnType("longtext");
                entity.Property(c => c.AllowedIdentityProviders).HasColumnType("longtext");
                entity.Property(c => c.AllowedMfaMethods).HasColumnType("longtext");
                entity.Property(c => c.BackChannelLogoutUri).HasColumnType("longtext");
                entity.Property(c => c.FrontChannelLogoutUri).HasColumnType("longtext");
                entity.Property(c => c.PolicyUri).HasColumnType("longtext");
                entity.Property(c => c.TosUri).HasColumnType("longtext");
                entity.Property(c => c.LogoUri).HasColumnType("longtext");
                entity.Property(c => c.ClientUri).HasColumnType("longtext");
                entity.Property(c => c.CustomCssUrl).HasColumnType("longtext");
                entity.Property(c => c.CustomErrorPageUrl).HasColumnType("longtext");
                entity.Property(c => c.CustomJavaScriptUrl).HasColumnType("longtext");
                entity.Property(c => c.CustomLoginPageUrl).HasColumnType("longtext");
                entity.Property(c => c.CustomLogoutPageUrl).HasColumnType("longtext");
            });

            // Adjust long text fields for IdentityProvider and ClientIdentityProvider as well
            builder.Entity<IdentityProvider>(entity =>
            {
                entity.Property(ip => ip.ClaimMappingsJson).HasColumnType("longtext");
                entity.Property(ip => ip.SamlCertificate).HasColumnType("longtext");
            });

            builder.Entity<ClientIdentityProvider>(entity =>
            {
                entity.Property(cip => cip.OptionsJson).HasColumnType("longtext");
                entity.Property(cip => cip.ClaimMappingsJson).HasColumnType("longtext");
            });

            builder.Entity<Realm>(entity =>
            {
                entity.Property(r => r.RealmCustomCssUrl).HasColumnType("longtext");
                entity.Property(r => r.RealmLogoUri).HasColumnType("longtext");
                entity.Property(r => r.RealmPolicyUri).HasColumnType("longtext");
                entity.Property(r => r.RealmTosUri).HasColumnType("longtext");
                entity.Property(r => r.RealmUri).HasColumnType("longtext");
                entity.Property(r => r.DefaultAllowedMfaMethods).HasColumnType("longtext");
            });

            builder.Entity<PersistentQrSession>(entity =>
            {
                entity.Property(p => p.ReturnUrl).HasColumnType("longtext");
            });

            // Ensure audit log can store large payloads
            builder.Entity<AuditLog>(entity =>
            {
                entity.Property(a => a.Changes).HasColumnType("longtext");
            });
        }

        // Provider-specific tuning: PostgreSQL -> use text for large strings
        if (Database.ProviderName?.Contains("Npgsql", StringComparison.OrdinalIgnoreCase) == true)
        {
            builder.Entity<AuditLog>(entity =>
            {
                entity.Property(a => a.Changes).HasColumnType("text");
            });
        }

        // Provider-specific tuning: SQL Server -> nvarchar(max)
        if (Database.ProviderName?.Contains("SqlServer", StringComparison.OrdinalIgnoreCase) == true)
        {
            builder.Entity<AuditLog>(entity =>
            {
                entity.Property(a => a.Changes).HasColumnType("nvarchar(max)");
            });
        }
    }

    public override int SaveChanges()
    {
        ApplyTimestampsAndAuditEntries();
        return base.SaveChanges();
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        ApplyTimestampsAndAuditEntries();
        return await base.SaveChangesAsync(cancellationToken);
    }

    private void ApplyTimestampsAndAuditEntries()
    {
        var now = DateTime.UtcNow;
        var http = _httpContextAccessor?.HttpContext;
        var userId = http?.User?.FindFirst(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject)?.Value
                     ?? http?.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var userName = http?.User?.Identity?.Name;
        var ip = http?.Connection?.RemoteIpAddress?.ToString();

        ChangeTracker.DetectChanges();
        var entries = ChangeTracker.Entries()
            .Where(e => e.State == EntityState.Added || e.State == EntityState.Modified || e.State == EntityState.Deleted)
            .ToList();

        foreach (var entry in entries)
        {
            // Set CreatedAt/UpdatedAt/CreatedBy/UpdatedBy if present on the entity
            if (entry.State == EntityState.Added)
            {
                SetPropertyIfExists(entry, nameof(Client.CreatedAt), now);
                SetPropertyIfExists(entry, nameof(Client.UpdatedAt), now);
                if (!string.IsNullOrEmpty(userId)) SetPropertyIfExists(entry, nameof(Client.CreatedBy), userId);
                if (!string.IsNullOrEmpty(userId)) SetPropertyIfExists(entry, nameof(Client.UpdatedBy), userId);
            }
            else if (entry.State == EntityState.Modified)
            {
                SetPropertyIfExists(entry, nameof(Client.UpdatedAt), now);
                if (!string.IsNullOrEmpty(userId)) SetPropertyIfExists(entry, nameof(Client.UpdatedBy), userId);
            }

            // Build audit log for entity if not AuditLog itself
            if (entry.Entity is AuditLog)
                continue;

            var audit = new AuditLog
            {
                OccurredAt = now,
                UserId = userId,
                UserName = userName,
                IpAddress = ip,
                EntityType = entry.Entity.GetType().Name,
                EntityId = GetPrimaryKeyValue(entry),
                Action = entry.State switch
                {
                    EntityState.Added => AuditAction.Added.ToString(),
                    EntityState.Modified => AuditAction.Modified.ToString(),
                    EntityState.Deleted => AuditAction.Deleted.ToString(),
                    _ => AuditAction.Modified.ToString()
                }
            };

            // Capture property-level changes for Modified and Deleted. For Added, only new values are interesting.
            var changes = new List<object>();
            foreach (var prop in entry.Properties)
            {
                if (!prop.Metadata.IsPrimaryKey())
                {
                    object? oldVal = null;
                    object? newVal = null;

                    if (entry.State == EntityState.Added)
                    {
                        newVal = prop.CurrentValue;
                    }
                    else if (entry.State == EntityState.Deleted)
                    {
                        oldVal = prop.OriginalValue;
                    }
                    else if (entry.State == EntityState.Modified && prop.IsModified)
                    {
                        oldVal = prop.OriginalValue;
                        newVal = prop.CurrentValue;
                    }

                    if (oldVal != null || newVal != null)
                    {
                        changes.Add(new
                        {
                            Property = prop.Metadata.Name,
                            Old = oldVal,
                            New = newVal
                        });
                    }
                }
            }

            if (changes.Count > 0)
            {
                var json = JsonSerializer.Serialize(changes, new JsonSerializerOptions
                {
                    WriteIndented = false,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                });

                audit.Changes = json;
            }

            AuditLogs.Add(audit);
        }
    }

    private static void SetPropertyIfExists(Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry entry, string propertyName, object value)
    {
        var prop = entry.Metadata.FindProperty(propertyName);
        if (prop != null)
        {
            entry.CurrentValues[propertyName] = value;
        }
    }

    private static string GetPrimaryKeyValue(Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry entry)
    {
        var key = entry.Metadata.FindPrimaryKey();
        if (key == null) return string.Empty;
        var values = key.Properties.Select(p => entry.CurrentValues[p] ?? entry.OriginalValues[p]).ToArray();
        return string.Join("|", values.Select(v => v?.ToString()));
    }
}