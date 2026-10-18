using QRCoder;
using System.Text;

namespace Skybridge.WinClient.Services;

internal sealed record LanConnectionQrImage(byte[] PngBytes, int PixelSize);

/// <summary>Local QR rendering of the same public LAN hint used by copy/paste.</summary>
internal static class LanConnectionQrCode
{
    internal static async Task<T> RenderAsync<T>(LanConnectionInfoPublication publication,
        Func<LanConnectionQrImage, CancellationToken, Task<T>> decode, CancellationToken token) where T : class
    {
        ArgumentNullException.ThrowIfNull(decode);
        token.ThrowIfCancellationRequested();
        var rendered = Render(publication);
        token.ThrowIfCancellationRequested();
        // Retain an in-flight decoder until it actually completes; cancellation
        // or a changed owner must prevent the resulting pixels being published.
        var decoded = await decode(rendered, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        _ = publication.ReadCurrentText();
        return decoded ?? throw new InvalidDataException("The QR decoder returned no image.");
    }

    internal static LanConnectionQrImage Render(LanConnectionInfoPublication publication, int moduleScale = 6)
    {
        ArgumentNullException.ThrowIfNull(publication);
        if (moduleScale is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(moduleScale));
        var text = publication.ReadCurrentText();
        // M accommodates the complete bounded 2048-byte LAN hint. The fixed
        // black/white bitmap includes four quiet modules and integer scaling.
        // Explicit byte mode keeps the exact wire bytes independent of automatic
        // text-mode optimization. Independent mobile-decoder corpus checks cover
        // both this output and the earlier mixed-mode locator counterexample.
        using var data = QRCodeGenerator.GenerateQrCode(Encoding.UTF8.GetBytes(text), QRCodeGenerator.ECCLevel.M);
        using var png = new PngByteQRCode(data);
        var bytes = png.GetGraphic(moduleScale, drawQuietZones: true);
        var result = new LanConnectionQrImage(bytes, checked(data.ModuleMatrix.Count * moduleScale));
        _ = publication.ReadCurrentText();
        return result;
    }
}
