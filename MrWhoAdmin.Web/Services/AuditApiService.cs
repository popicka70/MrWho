using System.Text.Json;
using MrWho.Shared.Models; // if needed later

namespace MrWhoAdmin.Web.Services;

public interface IAuditApiService
{
    Task<AuditQueryResult?> QueryAsync(int page = 1, int pageSize = 100, string? category = null, string? eventType = null, string? level = null, string? actorUserId = null, string? actorClientId = null, DateTime? fromUtc = null, DateTime? toUtc = null);
    Task<List<AuditEventDto>?> LatestAsync(int count = 50);
    Task<AuditChainVerifyResult?> VerifyChainAsync(long? startId = null, long? endId = null);
}

public class AuditApiService : IAuditApiService
{
    private readonly HttpClient _http;
    private readonly ILogger<AuditApiService> _logger;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public AuditApiService(HttpClient http, ILogger<AuditApiService> logger)
    { _http = http; _logger = logger; }

    public async Task<AuditQueryResult?> QueryAsync(int page = 1, int pageSize = 100, string? category = null, string? eventType = null, string? level = null, string? actorUserId = null, string? actorClientId = null, DateTime? fromUtc = null, DateTime? toUtc = null)
    {
        try
        {
            var qs = new List<string> { $"page={page}", $"pageSize={pageSize}" };
            void add(string name, string? value) { if (!string.IsNullOrWhiteSpace(value)) { qs.Add($"{name}={Uri.EscapeDataString(value)}"); } }
            add("category", category); add("eventType", eventType); add("level", level); add("actorUserId", actorUserId); add("actorClientId", actorClientId);
            if (fromUtc.HasValue) {
                add("fromUtc", fromUtc.Value.ToString("o"));
            }

            if (toUtc.HasValue) {
                add("toUtc", toUtc.Value.ToString("o"));
            }

            var url = "debug/audit-chain/query?" + string.Join('&', qs);
            var resp = await _http.GetAsync(url);
            if (!resp.IsSuccessStatusCode) {
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<AuditQueryResult>(json, _json);
        }
        catch (Exception ex)
        { _logger.LogError(ex, "Audit query failed"); return null; }
    }

    public async Task<List<AuditEventDto>?> LatestAsync(int count = 50)
    {
        try
        {
            var resp = await _http.GetAsync($"debug/audit-chain/latest?count={count}");
            if (!resp.IsSuccessStatusCode) {
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<List<AuditEventDto>>(json, _json);
        }
        catch (Exception ex) { _logger.LogError(ex, "Audit latest failed"); return null; }
    }

    public async Task<AuditChainVerifyResult?> VerifyChainAsync(long? startId = null, long? endId = null)
    {
        try
        {
            var qs = new List<string>();
            if (startId.HasValue) {
                qs.Add("startId=" + startId.Value);
            }

            if (endId.HasValue) {
                qs.Add("endId=" + endId.Value);
            }

            var url = "debug/audit-chain" + (qs.Count > 0 ? ("?" + string.Join('&', qs)) : string.Empty);
            var resp = await _http.GetAsync(url);
            if (!resp.IsSuccessStatusCode) {
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<AuditChainVerifyResult>(json, _json);
        }
        catch (Exception ex) { _logger.LogError(ex, "Audit verify failed"); return null; }
    }
}

public record AuditEventDto(long Id, DateTime TimestampUtc, string Category, string EventType, string? Level, string? ActorUserId, string? ActorClientId, string? IpAddress, string? DataJson);
public record AuditQueryResult(int Page, int PageSize, int Total, List<AuditEventDto> Items);
public record AuditChainVerifyResult(int Count, bool Ok, long? FirstId, long? LastId, DateTime VerifiedAtUtc, List<object>? Issues);
