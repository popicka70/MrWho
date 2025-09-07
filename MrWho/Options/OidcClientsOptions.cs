using System;

namespace MrWho.Options;

public class OidcClientsOptions
{
    public ClientOptions Admin { get; set; } = new();
    public ClientOptions Demo1 { get; set; } = new();
    public ClientOptions Nuget { get; set; } = new();
    public ClientOptions Default { get; set; } = new();
    public ClientOptions ServiceM2M { get; set; } = new();
    public ClientOptions M2M { get; set; } = new();

    public class ClientOptions
    {
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public string[] RedirectUris { get; set; } = Array.Empty<string>();
        public string[] PostLogoutRedirectUris { get; set; } = Array.Empty<string>();
    }
}
