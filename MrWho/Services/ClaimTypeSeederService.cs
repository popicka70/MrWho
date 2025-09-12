using Microsoft.EntityFrameworkCore;
using MrWho.Data;
using MrWho.Models;
using MrWho.Shared.Models;
using System.Globalization;

namespace MrWho.Services;

public interface IClaimTypeSeederService
{
    Task SeedClaimTypesAsync();
}

public class ClaimTypeSeederService : IClaimTypeSeederService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ClaimTypeSeederService> _logger;

    public ClaimTypeSeederService(ApplicationDbContext context, ILogger<ClaimTypeSeederService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task SeedClaimTypesAsync()
    {
        // Ensure database reachable
        if (!await _context.Database.CanConnectAsync()) return;

        var existing = await _context.ClaimTypes.AsNoTracking().ToListAsync();
        var existingTypes = existing.Select(c => c.Type).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // 1. Seed standard claims
        int order = 0;
        foreach (var sc in CommonClaimTypes.StandardClaims)
        {
            if (!existingTypes.Contains(sc.Type))
            {
                _context.ClaimTypes.Add(new ClaimType
                {
                    Type = sc.Type,
                    DisplayName = sc.DisplayName,
                    Description = sc.Description,
                    Category = "standard",
                    IsStandard = true,
                    IsEnabled = true,
                    SortOrder = order++,
                    CreatedBy = "System"
                });
            }
        }

        // 2. Import distinct claim types referenced by identity resource claims, scope claims, api resource claims, user claims
        var referenced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        referenced.UnionWith((await _context.IdentityResourceClaims.Select(c => c.ClaimType).Distinct().ToListAsync()).Where(s => !string.IsNullOrWhiteSpace(s))!);
        referenced.UnionWith((await _context.ScopeClaims.Select(c => c.ClaimType).Distinct().ToListAsync()).Where(s => !string.IsNullOrWhiteSpace(s))!);
        referenced.UnionWith((await _context.ApiResourceClaims.Select(c => c.ClaimType).Distinct().ToListAsync()).Where(s => !string.IsNullOrWhiteSpace(s))!);
        referenced.UnionWith((await _context.UserClaims.Select(c => c.ClaimType).Distinct().ToListAsync()).Where(s => !string.IsNullOrWhiteSpace(s))!);

        foreach (var type in referenced)
        {
            if (string.IsNullOrWhiteSpace(type)) continue;
            if (!existingTypes.Contains(type) && !CommonClaimTypes.StandardClaims.Any(s => s.Type == type))
            {
                var display = CultureInfo.CurrentCulture.TextInfo.ToTitleCase(type.Replace("_", " ").ToLowerInvariant());
                _context.ClaimTypes.Add(new ClaimType
                {
                    Type = type,
                    DisplayName = display,
                    Description = "Imported custom claim type",
                    Category = "custom",
                    IsStandard = false,
                    IsEnabled = true,
                    SortOrder = 1000,
                    CreatedBy = "System"
                });
            }
        }

        await _context.SaveChangesAsync();
    }
}
