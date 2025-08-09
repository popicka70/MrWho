using System;
using System.IO;
using QRCoder;

namespace MrWho.Services;

public interface IQrCodeService
{
    string GeneratePngDataUri(string content, int pixelsPerModule = 5);
}

public sealed class QrCodeService : IQrCodeService
{
    public string GeneratePngDataUri(string content, int pixelsPerModule = 5)
    {
        if (string.IsNullOrWhiteSpace(content))
            throw new ArgumentException("QR content is required", nameof(content));

        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(content, QRCodeGenerator.ECCLevel.Q);
        var png = new PngByteQRCode(data);
        var bytes = png.GetGraphic(pixelsPerModule);
        var base64 = Convert.ToBase64String(bytes);
        return $"data:image/png;base64,{base64}";
    }
}
