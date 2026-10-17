using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioFlacDecoderTests
{
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "Fixtures", "flac-decoder-v1");
    internal static IEnumerable<(string Name, Func<Task> Run)> Cases
    {
        get
        {
            yield return ("FLAC fixture bytes match the independent shared manifest", Manifest);
            foreach (var path in Directory.GetFiles(Root, "*.pcm").Order(StringComparer.Ordinal))
            {
                var name = Path.GetFileNameWithoutExtension(path);
                yield return ($"native FLAC preserves exact golden sample bytes: {name}", () => Golden(name));
            }
            foreach (var name in new[] { "frame-crc-mismatch", "valid-crc-wrong-pcm-md5", "missing-silent-middle-must-not-recover" })
                yield return ($"native FLAC rejects terminal stream corruption: {name}", () => Corruption(name));
            yield return ("native FLAC rejects unknown finite length before reading samples", UnknownLength);
            yield return ("native FLAC propagates original source failure across C callbacks and stays failed", SourceFailure);
            yield return ("native FLAC revocation within a callback returns no samples and stays failed", Revoked);
            yield return ("native FLAC cancellation retains an uncooperative read until its actual completion", PendingRead);
            yield return ("native FLAC rejects mismatched declarations and closed decoder operations", MismatchAndClose);
        }
    }
    internal static byte[] Bytes(string name, string extension = ".flac") => File.ReadAllBytes(Path.Combine(Root, name + extension));
    internal static Task<AudioFlacMetadata> Metadata(byte[] bytes) => AudioFlacFile.InspectAsync(bytes.Length,
        (offset, count, _) => Task.FromResult(bytes.AsSpan(checked((int)offset), count).ToArray()), CancellationToken.None);
    private static Task Manifest()
    {
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Root, "manifest.json")));
        foreach (var item in manifest.RootElement.GetProperty("files").EnumerateArray())
        {
            var bytes = File.ReadAllBytes(Path.Combine(Root, item.GetProperty("path").GetString() ?? throw new Exception("Missing fixture path.")));
            Require(bytes.Length == item.GetProperty("bytes").GetInt32() &&
                Convert.ToHexStringLower(SHA256.HashData(bytes)) == item.GetProperty("sha256").GetString(), "Fixture differs from its sealed reference.");
        }
        return Task.CompletedTask;
    }
    private static async Task Golden(string name)
    {
        byte[] source = Bytes(name), expected = Bytes(name, ".pcm"); var metadata = await Metadata(source);
        int maximumRead = 0; bool forcedGc = false;
        using var decoder = new AudioFlacPcmDecoder(source.Length, (offset, count, _) =>
        {
            maximumRead = Math.Max(count, maximumRead);
            if (!forcedGc) { forcedGc = true; GC.Collect(); GC.WaitForPendingFinalizers(); }
            return Task.FromResult(source.AsSpan((int)offset, count).ToArray());
        }, metadata);
        int matched = 0;
        while (true)
        {
            switch (decoder.Next(() => { }, CancellationToken.None))
            {
                case AudioFlacDecodeStep.Frame frame:
                    Require(frame.FirstIndex == (ulong)matched / metadata.DecodedFormat.BytesPerFrame &&
                        frame.Bytes.Length == frame.FrameCount * metadata.DecodedFormat.BytesPerFrame &&
                        matched <= expected.Length && frame.Bytes.Length <= expected.Length - matched &&
                        frame.Bytes.AsSpan().SequenceEqual(expected.AsSpan(matched, frame.Bytes.Length)), "Decoded samples differ from the independent reference.");
                    matched += frame.Bytes.Length; break;
                case AudioFlacDecodeStep.Complete complete:
                    Require(matched == expected.Length && complete.Receipt.SourceFrames == (ulong)(matched / metadata.DecodedFormat.BytesPerFrame) &&
                        complete.Receipt.EncodedBytes == (ulong)source.Length && complete.Receipt.Md5Available == (metadata.PcmMd5Hex is not null) &&
                        complete.Receipt.Md5Verified == complete.Receipt.Md5Available && maximumRead is > 0 and <= 65536,
                        "Decode completion lacks exact count, EOF or correctly represented MD5 availability.");
                    return;
            }
        }
    }
    private static async Task Corruption(string name)
    {
        var source = Bytes(name); var metadata = await Metadata(source);
        using var decoder = Decoder(source, metadata);
        var failure = Throws<AudioFlacDecodeException>(() => DecodeAll(decoder));
        Require(failure.Status is AudioFlacDecoderStatus.CodecError or AudioFlacDecoderStatus.Md5Mismatch,
            "Corrupt frames were rejected for an unrelated condition.");
        Require(ReferenceEquals(failure, Throws<AudioFlacDecodeException>(() => decoder.Next(() => { }, CancellationToken.None))), "Failed decoder resumed or replaced its cause.");
    }
    private static async Task UnknownLength()
    {
        var source = Bytes("unknown-length-not-admitted-by-finite-decoder"); var metadata = await Metadata(source);
        Require(metadata.TotalFrames is null, "Unknown frame count fixture changed.");
        _ = Throws<InvalidDataException>(() => { using var decoder = Decoder(source, metadata); });
    }
    private static async Task SourceFailure()
    {
        var source = Bytes("golden-24-2"); var metadata = await Metadata(source); var expected = new IOException("controlled source failure");
        using var decoder = new AudioFlacPcmDecoder(source.Length, (_, _, _) => Task.FromException<byte[]>(expected), metadata);
        Require(ReferenceEquals(expected, Throws<IOException>(() => decoder.Next(() => { }, CancellationToken.None))), "Native callback lost original I/O failure.");
        Require(ReferenceEquals(expected, Throws<IOException>(() => decoder.Next(() => { }, CancellationToken.None))), "Failed source was retried implicitly.");
    }
    private static async Task Revoked()
    {
        var source = Bytes("golden-24-2"); var metadata = await Metadata(source); bool revoked = false;
        var expected = new InvalidOperationException("controlled authorization revocation");
        using var decoder = new AudioFlacPcmDecoder(source.Length, (offset, count, _) =>
        { revoked = true; return Task.FromResult(source.AsSpan((int)offset, count).ToArray()); }, metadata);
        Require(ReferenceEquals(expected, Throws<InvalidOperationException>(() => decoder.Next(() => { if (revoked) throw expected; }, CancellationToken.None))),
            "Revoked read escaped as decoded samples.");
        Require(ReferenceEquals(expected, Throws<InvalidOperationException>(() => decoder.Next(() => { }, CancellationToken.None))), "Revoked decoder resumed.");
    }
    private static async Task PendingRead()
    {
        var source = Bytes("golden-24-2"); var metadata = await Metadata(source);
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var decoder = new AudioFlacPcmDecoder(source.Length, async (offset, count, _) =>
        { entered.TrySetResult(); await release.Task; return source.AsSpan((int)offset, count).ToArray(); }, metadata);
        var operation = Task.Run(() => decoder.Next(() => { }, cancellation.Token));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancellation.Cancel();
            await Task.Delay(30);
            Require(!operation.IsCompleted, "Cancellation falsely released an active native callback/source read.");
        }
        finally { release.TrySetResult(); }
        try { await operation.WaitAsync(TimeSpan.FromSeconds(5)); throw new Exception("Cancelled source returned samples."); }
        catch (OperationCanceledException failure) { Require(failure.CancellationToken == cancellation.Token, "Cancellation provenance changed."); }
        _ = Throws<OperationCanceledException>(() => decoder.Next(() => { }, CancellationToken.None));
    }
    private static async Task MismatchAndClose()
    {
        var source = Bytes("golden-24-2"); var metadata = await Metadata(source);
        using (var decoder = Decoder(source, metadata with { TotalFrames = (metadata.TotalFrames ?? throw new Exception("Missing fixture sample count.")) + 1 }))
            Require(Throws<AudioFlacDecodeException>(() => DecodeAll(decoder)).Status == AudioFlacDecoderStatus.MetadataMismatch, "Metadata from another declaration was admitted.");
        var closed = Decoder(source, metadata); closed.Dispose(); closed.Dispose();
        _ = Throws<ObjectDisposedException>(() => DecodeAll(closed));
    }
    private static AudioFlacPcmDecoder Decoder(byte[] source, AudioFlacMetadata metadata) =>
        new(source.Length, (offset, count, _) => Task.FromResult(source.AsSpan((int)offset, count).ToArray()), metadata);
    private static void DecodeAll(AudioFlacPcmDecoder decoder)
    {
        for (int i = 0; i < 100000; i++) if (decoder.Next(() => { }, CancellationToken.None) is AudioFlacDecodeStep.Complete) return;
        throw new Exception("Fixture decoder did not reach a bounded terminal state.");
    }
    private static T Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T error) { return error; } throw new Exception("Expected " + typeof(T).Name); }
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
}
