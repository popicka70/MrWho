using System.Net.Http.Json;
using MrWho.Shared.Models;

namespace MrWhoAdmin.Web.Services;

public interface IClaimTypesApiService
{
    Task<List<ClaimTypeInfo>?> GetAsync();
    Task<ClaimTypeInfo?> GetAsync(string type);
    Task<ClaimTypeInfo?> CreateAsync(ClaimTypeInfo claimType, bool isEnabled = true, bool isObsolete = false, int? sortOrder = null, string? category = null, string? description = null);
    Task<ClaimTypeInfo?> UpdateAsync(ClaimTypeInfo claimType, bool isEnabled = true, bool isObsolete = false, int? sortOrder = null, string? category = null, string? description = null);
    Task<bool> DeleteAsync(string type);
}

public class ClaimTypesApiService : IClaimTypesApiService
{
    private readonly HttpClient _http;
    private readonly ILogger<ClaimTypesApiService> _logger;

    public ClaimTypesApiService(HttpClient http, ILogger<ClaimTypesApiService> logger)
    {
        _http = http;
        _logger = logger;
    }

    public async Task<List<ClaimTypeInfo>?> GetAsync()
    {
        try { return await _http.GetFromJsonAsync<List<ClaimTypeInfo>>("api/claimtypes"); } catch (Exception ex) { _logger.LogError(ex, "Get claim types failed"); return null; }
    }

    public async Task<ClaimTypeInfo?> GetAsync(string type)
    {
        try { return await _http.GetFromJsonAsync<ClaimTypeInfo>($"api/claimtypes/{Uri.EscapeDataString(type)}"); } catch (Exception ex) { _logger.LogError(ex, "Get claim type failed"); return null; }
    }

    public async Task<ClaimTypeInfo?> CreateAsync(ClaimTypeInfo claimType, bool isEnabled = true, bool isObsolete = false, int? sortOrder = null, string? category = null, string? description = null)
    {
        try
        {
            var req = new { claimType.Type, DisplayName = claimType.DisplayName, Description = description ?? claimType.Description, Category = category, IsEnabled = isEnabled, IsObsolete = isObsolete, SortOrder = sortOrder };
            var resp = await _http.PostAsJsonAsync("api/claimtypes", req);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            return await resp.Content.ReadFromJsonAsync<ClaimTypeInfo>();
        }
        catch (Exception ex) { _logger.LogError(ex, "Create claim type failed"); return null; }
    }

    public async Task<ClaimTypeInfo?> UpdateAsync(ClaimTypeInfo claimType, bool isEnabled = true, bool isObsolete = false, int? sortOrder = null, string? category = null, string? description = null)
    {
        try
        {
            var req = new { claimType.Type, DisplayName = claimType.DisplayName, Description = description ?? claimType.Description, Category = category, IsEnabled = isEnabled, IsObsolete = isObsolete, SortOrder = sortOrder };
            var resp = await _http.PutAsJsonAsync($"api/claimtypes/{Uri.EscapeDataString(claimType.Type)}", req);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            return await resp.Content.ReadFromJsonAsync<ClaimTypeInfo>();
        }
        catch (Exception ex) { _logger.LogError(ex, "Update claim type failed"); return null; }
    }

    public async Task<bool> DeleteAsync(string type)
    {
        try { var resp = await _http.DeleteAsync($"api/claimtypes/{Uri.EscapeDataString(type)}"); return resp.IsSuccessStatusCode; } catch (Exception ex) { _logger.LogError(ex, "Delete claim type failed"); return false; }
    }
}
