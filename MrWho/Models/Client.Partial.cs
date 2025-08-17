using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using MrWho.Shared;

namespace MrWho.Models;

public partial class Client
{
    // Navigation to external IdPs allowed for this client
    public virtual ICollection<ClientIdentityProvider> IdentityProviders { get; set; } = new List<ClientIdentityProvider>();
}
