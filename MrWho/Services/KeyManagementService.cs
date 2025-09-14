using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MrWho.Data;
using MrWho.Models;
using MrWho.Options;

namespace MrWho.Services;

public class KeyManagementService : IKeyManagementService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<KeyManagementService> _logger;
    private readonly IOptions<KeyManagementOptions> _options;

    public KeyManagementService(IServiceProvider services, ILogger<KeyManagementService> logger, IOptions<KeyManagementOptions> options)
    {
        _services = services;
        _logger = logger;
        _options = options;
    }

    public async Task EnsureInitializedAsync(CancellationToken ct = default)
    {
        if (!_options.Value.Enabled)
        {
            return;
        }

        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        // Ensure at least one active signing key exists
        var now = DateTime.UtcNow;
        var anySigning = await db.KeyMaterials.AnyAsync(k => k.Use == "sig" && k.Status != KeyMaterialStatus.Revoked, ct);
        if (!anySigning)
        {
            _logger.LogInformation("No signing keys found. Generating initial signing key.");
            var signing = GenerateRsaKey(_options.Value.SigningKeySize, use: "sig", _options.Value.SigningAlgorithm, primary: true, now);
            db.KeyMaterials.Add(signing);
        }

        // Ensure at least one active encryption key exists
        var anyEnc = await db.KeyMaterials.AnyAsync(k => k.Use == "enc" && k.Status != KeyMaterialStatus.Revoked, ct);
        if (!anyEnc)
        {
            _logger.LogInformation("No encryption keys found. Generating initial encryption key.");
            var enc = GenerateRsaKey(_options.Value.EncryptionKeySize, use: "enc", _options.Value.EncryptionAlgorithm, primary: true, now);
            db.KeyMaterials.Add(enc);
        }

        await db.SaveChangesAsync(ct);

        // Apply rotation policy: if primary key is older than rotation interval, create a new one and mark current as retiring.
        await ApplyRotationIfNeededAsync(db, now, ct);
    }

    public async Task<(IReadOnlyList<SecurityKey> signingKeys, IReadOnlyList<SecurityKey> encryptionKeys)> GetActiveKeysAsync(CancellationToken ct = default)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var now = DateTime.UtcNow;

        var keys = await db.KeyMaterials
            .Where(k => k.Status == KeyMaterialStatus.Active || k.Status == KeyMaterialStatus.Retiring)
            .OrderByDescending(k => k.IsPrimary)
            .ThenByDescending(k => k.ActivateAt)
            .ToListAsync(ct);

        var signingKeys = new List<SecurityKey>();
        var encKeys = new List<SecurityKey>();

        foreach (var km in keys)
        {
            try
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(km.PrivateKeyPem);
                var key = new RsaSecurityKey(rsa) { KeyId = km.Kid };
                if (km.Use == "sig")
                {
                    signingKeys.Add(key);
                }
                else if (km.Use == "enc")
                {
                    encKeys.Add(key);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load key {Kid}", km.Kid);
            }
        }

        return (signingKeys, encKeys);
    }

    private async Task ApplyRotationIfNeededAsync(ApplicationDbContext db, DateTime now, CancellationToken ct)
    {
        var opts = _options.Value;
        var rotateBefore = now - opts.RotationInterval;

        foreach (var use in new[] { "sig", "enc" })
        {
            var primary = await db.KeyMaterials.Where(k => k.Use == use && k.IsPrimary && k.Status == KeyMaterialStatus.Active)
                .OrderByDescending(k => k.ActivateAt).FirstOrDefaultAsync(ct);
            if (primary == null)
            {
                continue;
            }

            if (primary.ActivateAt <= rotateBefore)
            {
                _logger.LogInformation("Rotating {Use} key: {Kid}", use, primary.Kid);

                // Create new key
                var algo = use == "sig" ? opts.SigningAlgorithm : opts.EncryptionAlgorithm;
                var size = use == "sig" ? opts.SigningKeySize : opts.EncryptionKeySize;
                var next = GenerateRsaKey(size, use, algo, primary: true, now);

                // Demote old primary to retiring and set retire date
                primary.IsPrimary = false;
                primary.Status = KeyMaterialStatus.Retiring;
                primary.RetireAt = now.Add(opts.OverlapPeriod);

                // Activate new key immediately
                next.Status = KeyMaterialStatus.Active;
                next.ActivateAt = now;

                db.KeyMaterials.Add(next);

                await db.SaveChangesAsync(ct);
            }

            // Expire retiring keys past retireAt
            var retiring = await db.KeyMaterials.Where(k => k.Use == use && k.Status == KeyMaterialStatus.Retiring && k.RetireAt < now).ToListAsync(ct);
            foreach (var r in retiring)
            {
                r.Status = KeyMaterialStatus.Retired;
            }
            if (retiring.Count > 0)
            {
                await db.SaveChangesAsync(ct);
            }
        }
    }

    private static KeyMaterial GenerateRsaKey(int keySize, string use, string algorithm, bool primary, DateTime now)
    {
        using var rsa = RSA.Create(keySize);
        var pkcs8 = ExportPrivateKeyPkcs8Pem(rsa);
        return new KeyMaterial
        {
            Use = use,
            Algorithm = algorithm,
            KeyType = "RSA",
            KeySize = keySize,
            PrivateKeyPem = pkcs8,
            CreatedAt = now,
            ActivateAt = now,
            IsPrimary = primary,
            Status = KeyMaterialStatus.Active,
            Kid = CreateKid(rsa)
        };
    }

    private static string ExportPrivateKeyPkcs8Pem(RSA rsa)
    {
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        return new string(PemEncoding.Write("PRIVATE KEY", pkcs8));
    }

    private static string CreateKid(RSA rsa)
    {
        // kid = SHA-256 thumbprint over the public key parameters
        var parameters = rsa.ExportSubjectPublicKeyInfo();
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(parameters);
        return Base64UrlEncoder.Encode(hash);
    }
}
