namespace MrWho.Shared.Models;

public class ApiUsageOverviewDto
{
    public long TotalRequests { get; set; }
    public int UniqueClients { get; set; }
    public long RequestsLast24H { get; set; }
    public long RequestsLast7D { get; set; }
}

public class ApiUsageTopClientDto
{
    public string ClientId { get; set; } = "<unknown>";
    public long Requests { get; set; }
}

public class ApiEndpointUsageDto
{
    public string Endpoint { get; set; } = string.Empty; // e.g., EntityType/Action
    public long Requests { get; set; }
}

public class ApiUsageTimeSeriesPointDto
{
    public DateTime Date { get; set; }
    public long Requests { get; set; }
}