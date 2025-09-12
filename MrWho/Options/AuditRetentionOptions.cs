using System.ComponentModel.DataAnnotations;

namespace MrWho.Options;

public class AuditRetentionOptions
{
    public const string SectionName = "AuditRetention";

    [Range(1, 366)]
    public int KeepDays { get; set; } = 30;

    [Range(100, 1_000_000)]
    public int MinEventsToKeep { get; set; } = 10_000; // safety floor

    [Range(100, 100_000)]
    public int BatchSize { get; set; } = 2_000; // per cleanup iteration
}
