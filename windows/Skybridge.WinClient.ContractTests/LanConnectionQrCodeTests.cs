using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

internal static class LanConnectionQrCodeTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("LAN QR renders bounded monochrome PNGs for Unicode and maximum device names", PngBounds),
        ("LAN QR rejects revoked ownership before starting image decoding", RevokedBeforeDecode),
        ("LAN QR rechecks a changed route after asynchronous image decoding", ChangedDuringDecode),
        ("LAN QR cancellation retains a noncooperative decoder and cannot publish its pixels", CancelDuringDecode),
        ("LAN QR preserves image decoding failures and rejects a missing image", DecodeFailures),
        ("LAN publication requires the same adapter address and interface index", CurrentRoute)
    ];

    private static IPEndPoint Endpoint() => new(IPAddress.Parse("192.168.1.60"), 50978);
    private static RemoteControlPairingMaterial Identity(string name) => RemoteControlPairingMaterial.CreateProtocolIdentity(
        "id:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", name, Enumerable.Repeat((byte)0x33, 1952).ToArray());
    private static LanConnectionInfoPublication Publication(Func<IPEndPoint>? current = null, string name = "书房 Windows 🧑‍💻") =>
        new(Identity(name), current ?? Endpoint);
    private static readonly (string Name, string DeviceName)[] Vectors = CreateVectors();

    private static (string Name, string DeviceName)[] CreateVectors()
    {
        var vectors = new List<(string Name, string DeviceName)>
        {
            ("unicode", "书房 Windows 🧑‍💻"), ("maximum-name", new string('界', 128)), ("ascii", "Living room Windows"),
            ("maximum-ascii", new string('W', 128)), ("maximum-emoji", string.Concat(Enumerable.Repeat("🎵", 64)))
        };
        const string alphabet = "界家机橋αЖΩあカçA7-_";
        var random = new Random(20261018);
        for (int i = 0; i < 16; i++)
            vectors.Add(($"varied-{i:D2}", new string(Enumerable.Range(0, 128).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray())));
        return vectors.ToArray();
    }

    private static Task PngBounds()
    {
        foreach (var vector in Vectors)
        {
            var publication = Publication(name: vector.DeviceName);
            var image = LanConnectionQrCode.Render(publication);
            Require(image.PngBytes.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }), "Missing PNG signature.");
            Require(BinaryPrimitives.ReadUInt32BigEndian(image.PngBytes.AsSpan(16, 4)) == image.PixelSize &&
                BinaryPrimitives.ReadUInt32BigEndian(image.PngBytes.AsSpan(20, 4)) == image.PixelSize &&
                image.PixelSize is >= 174 and <= 1110 && image.PixelSize % 6 == 0 &&
                image.PngBytes[24] == 1 && image.PngBytes[25] == 0, "QR bitmap lost its bounded integer grid or monochrome format.");
        }
        foreach (int scale in new[] { 0, 9 })
            Throws<ArgumentOutOfRangeException>(() => LanConnectionQrCode.Render(Publication(), scale));
        return Task.CompletedTask;
    }

    private static async Task RevokedBeforeDecode()
    {
        bool current = true; int decodes = 0;
        var expected = new InvalidOperationException("Listener retired.");
        var publication = Publication(() => current ? Endpoint() : throw expected);
        current = false;
        var observed = await ThrowsAsync<InvalidOperationException>(() => LanConnectionQrCode.RenderAsync(publication,
            (_, _) => { decodes++; return Task.FromResult("pixels"); }, default));
        Require(ReferenceEquals(expected, observed) && decodes == 0, "A stale owner reached the image decoder.");
    }

    private static async Task ChangedDuringDecode()
    {
        var route = Endpoint();
        var publication = Publication(() => route);
        var decode = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var rendering = LanConnectionQrCode.RenderAsync(publication, (_, _) => decode.Task, default);
        route.Port++;
        decode.SetResult("old pixels");
        await ThrowsAsync<InvalidOperationException>(() => rendering);
    }

    private static async Task CancelDuringDecode()
    {
        using var cancellation = new CancellationTokenSource();
        var decode = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var rendering = LanConnectionQrCode.RenderAsync(Publication(), (_, _) => decode.Task, cancellation.Token);
        cancellation.Cancel();
        Require(!rendering.IsCompleted, "A pending decoder was abandoned during cancellation.");
        decode.SetResult("late pixels");
        var failure = await ThrowsAsync<OperationCanceledException>(() => rendering);
        Require(failure.CancellationToken == cancellation.Token, "Cancellation lost its owner.");
    }

    private static async Task DecodeFailures()
    {
        var expected = new IOException("Image decoder failed.");
        var observed = await ThrowsAsync<IOException>(() => LanConnectionQrCode.RenderAsync(Publication(),
            (_, _) => Task.FromException<string>(expected), default));
        Require(ReferenceEquals(expected, observed), "A decoder failure was replaced or hidden.");
        await ThrowsAsync<InvalidDataException>(() => LanConnectionQrCode.RenderAsync(Publication(),
            (_, _) => Task.FromResult<string>(null!), default));
    }

    private static Task CurrentRoute()
    {
        var selected = new RemoteControlNetworkInterface("adapter-a", "Ethernet", Endpoint().Address, 7);
        WindowsLanConnectionInfo.RequireCurrentRoute(selected, [selected with { Name = "Renamed adapter" }]);
        foreach (var current in new IReadOnlyList<RemoteControlNetworkInterface>[]
        {
            [], [selected with { AdapterId = "adapter-b" }], [selected with { InterfaceIndex = 8 }],
            [selected with { Address = IPAddress.Parse("192.168.1.61") }]
        }) Throws<InvalidOperationException>(() => WindowsLanConnectionInfo.RequireCurrentRoute(selected, current));
        return Task.CompletedTask;
    }

    internal static void ExportImages(string directory)
    {
        if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("QR evidence output already exists.");
        Directory.CreateDirectory(directory);
        var entries = new List<object>();
        foreach (var vector in Vectors)
        {
            var publication = Publication(name: vector.DeviceName);
            var image = LanConnectionQrCode.Render(publication);
            File.WriteAllBytes(Path.Combine(directory, vector.Name + ".png"), image.PngBytes);
            File.WriteAllText(Path.Combine(directory, vector.Name + ".txt"), publication.ReadCurrentText(), new UTF8Encoding(false));
            entries.Add(new { name = vector.Name, pixelSize = image.PixelSize, moduleScale = 6, quietModules = 4,
                sha256 = Convert.ToHexStringLower(SHA256.HashData(image.PngBytes)) });
        }
        File.WriteAllText(Path.Combine(directory, "manifest.json"), JsonSerializer.Serialize(new
            { schemaVersion = 1, kind = "synthetic-public-lan-qr-vectors", entries }, new JsonSerializerOptions { WriteIndented = true }) + "\n");
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static T Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
