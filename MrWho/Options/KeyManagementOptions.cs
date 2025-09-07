namespace MrWho.Options;

public class KeyManagementOptions
{
    public const string SectionName = "KeyManagement";

    public bool Enabled { get; set; } = true;

    // RSA key size
    public int SigningKeySize { get; set; } = 2048;
    public int EncryptionKeySize { get; set; } = 2048;

    // Rotation policy
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan OverlapPeriod { get; set; } = TimeSpan.FromDays(7);

    // Algorithms
    public string SigningAlgorithm { get; set; } = "RS256";
    // Prefer RSA-OAEP for broad compatibility
    public string EncryptionAlgorithm { get; set; } = "RSA-OAEP";

    // Whether to disable access token encryption (OpenIddict default is encrypted) - keep compat with current
    public bool DisableAccessTokenEncryption { get; set; } = true;
}
