using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MrWho.Shared;

namespace MrWho.Models;

public partial class Client
{
    // JAR/JARM (Phase 1.5 preview) configuration fields
    public JarMode? JarMode { get; set; } // Disabled|Optional|Required
    public JarmMode? JarmMode { get; set; } // Disabled|Optional|Required
    public bool? RequireSignedRequestObject { get; set; } = true; // enforce signed request objects by default
    [StringLength(400)] public string? AllowedRequestObjectAlgs { get; set; } // CSV list of allowed algs (e.g. "RS256,HS256")

    // Navigation to external IdPs allowed for this client
    public virtual ICollection<ClientIdentityProvider> IdentityProviders { get; set; } = new List<ClientIdentityProvider>();
}
