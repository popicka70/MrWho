using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MrWho.Shared;

namespace MrWho.Models;

/// <summary>
/// Represents an OIDC client configuration
/// </summary>
public partial class Client
{
    // ...existing code...
    // JAR/JARM (Phase 1.5 preview)
    public JarMode? JarMode { get; set; } // Disabled/Optional/Required
    public JarmMode? JarmMode { get; set; } // Disabled/Optional/Required
    public bool? RequireSignedRequestObject { get; set; } = true; // default secure
    [StringLength(400)] public string? AllowedRequestObjectAlgs { get; set; } // CSV or JSON list (e.g., "RS256,HS256")
    // ...existing code...
}
