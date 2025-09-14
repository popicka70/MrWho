using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MrWho.Models;
using MrWho.Shared.Models;

namespace MrWho.Handlers.Users;

public class GetRolesHandler : IGetRolesHandler
{
    private readonly RoleManager<IdentityRole> _roleManager;

    public GetRolesHandler(RoleManager<IdentityRole> roleManager)
    {
        _roleManager = roleManager;
    }

    public async Task<PagedResult<RoleDto>> HandleAsync(int page, int pageSize, string? search)
    {
        if (page < 1) {
            page = 1;
        }

        if (pageSize < 1 || pageSize > 100) {
            pageSize = 10;
        }

        var query = _roleManager.Roles.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            query = query.Where(r => r.Name!.Contains(search));
        }

        var totalCount = await query.CountAsync();
        var roles = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(r => new RoleDto
            {
                Id = r.Id,
                Name = r.Name!,
                Description = null, // IdentityRole doesn't have Description by default
                IsEnabled = true, // IdentityRole doesn't have IsEnabled by default
                CreatedAt = DateTime.UtcNow, // IdentityRole doesn't have timestamps by default
                UpdatedAt = DateTime.UtcNow,
                CreatedBy = null,
                UpdatedBy = null
            })
            .ToListAsync();

        return new PagedResult<RoleDto>
        {
            Items = roles,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize,
            TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize)
        };
    }
}