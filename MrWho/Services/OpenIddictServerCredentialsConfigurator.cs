using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MrWho.Options;
using OpenIddict.Server;

namespace MrWho.Services;

/// <summary>
/// Post-configures OpenIddictServerOptions to use our persisted keys instead of development certificates.
/// Falls back to ephemeral keys if database is not ready or no keys exist yet.
/// </summary>
public class OpenIddictServerCredentialsConfigurator : IPostConfigureOptions<OpenIddictServerOptions>
{
    private readonly IKeyManagementService _keyService;
    private readonly IOptions<KeyManagementOptions> _options;

    public OpenIddictServerCredentialsConfigurator(IKeyManagementService keyService, IOptions<KeyManagementOptions> options)
    {
        _keyService = keyService;
        _options = options;
    }

    public void PostConfigure(string? name, OpenIddictServerOptions options)
    {
        try
        {
            // Ensure keys exist (may create them) and then load.
            _keyService.EnsureInitializedAsync().GetAwaiter().GetResult();
            var (signing, encryption) = _keyService.GetActiveKeysAsync().GetAwaiter().GetResult();

            options.EncryptionCredentials.Clear();
            options.SigningCredentials.Clear();

            if (signing.Count == 0 && encryption.Count == 0)
            {
                // Fallback to ephemeral RSA keys (do NOT dispose the RSA instances)
                var rsaSign = RSA.Create(_options.Value.SigningKeySize);
                var signKey = new RsaSecurityKey(rsaSign) { KeyId = Base64UrlEncoder.Encode(SHA256.HashData(rsaSign.ExportSubjectPublicKeyInfo())) };
                options.SigningCredentials.Add(new SigningCredentials(signKey, _options.Value.SigningAlgorithm));

                var rsaEnc = RSA.Create(_options.Value.EncryptionKeySize);
                var encKey = new RsaSecurityKey(rsaEnc) { KeyId = Base64UrlEncoder.Encode(SHA256.HashData(rsaEnc.ExportSubjectPublicKeyInfo())) };
                options.EncryptionCredentials.Add(new EncryptingCredentials(encKey, _options.Value.EncryptionAlgorithm, SecurityAlgorithms.Aes256CbcHmacSha512));
            }
            else
            {
                foreach (var sk in signing)
                {
                    options.SigningCredentials.Add(new SigningCredentials(sk, _options.Value.SigningAlgorithm));
                }
                foreach (var ek in encryption)
                {
                    options.EncryptionCredentials.Add(new EncryptingCredentials(ek, _options.Value.EncryptionAlgorithm, SecurityAlgorithms.Aes256CbcHmacSha512));
                }
            }

            if (_options.Value.DisableAccessTokenEncryption)
            {
                options.DisableAccessTokenEncryption = true;
            }
        }
        catch
        {
            // Last-resort fallback to ephemeral keys to avoid startup failure (do NOT dispose RSA)
            options.EncryptionCredentials.Clear();
            options.SigningCredentials.Clear();

            var rsaSign = RSA.Create(_options.Value.SigningKeySize);
            var signKey = new RsaSecurityKey(rsaSign) { KeyId = Base64UrlEncoder.Encode(SHA256.HashData(rsaSign.ExportSubjectPublicKeyInfo())) };
            options.SigningCredentials.Add(new SigningCredentials(signKey, _options.Value.SigningAlgorithm));

            var rsaEnc = RSA.Create(_options.Value.EncryptionKeySize);
            var encKey = new RsaSecurityKey(rsaEnc) { KeyId = Base64UrlEncoder.Encode(SHA256.HashData(rsaEnc.ExportSubjectPublicKeyInfo())) };
            options.EncryptionCredentials.Add(new EncryptingCredentials(encKey, _options.Value.EncryptionAlgorithm, SecurityAlgorithms.Aes256CbcHmacSha512));

            if (_options.Value.DisableAccessTokenEncryption)
            {
                options.DisableAccessTokenEncryption = true;
            }
        }
    }
}
