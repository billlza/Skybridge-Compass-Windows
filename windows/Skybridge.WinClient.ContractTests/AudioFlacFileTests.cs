using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioFlacFileTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("FLAC metadata matches 93 shared RFC and encoder fixtures", CommonVectors),
        ("FLAC metadata rejects every required header truncation", HeaderTruncations),
        ("FLAC metadata preserves I/O errors and requires exact read lengths", CallbackFailures),
        ("FLAC metadata rejects oversized sources before reading", FileBounds),
        ("FLAC metadata checks cancellation around the actual source read", CancellationChecks),
        ("FLAC metadata retains a noncooperative read until it completes", CancellationWaitsForRead),
        ("FLAC metadata bounds blocks comments and skipped metadata", ResourceBounds)
    ];

    private static async Task CommonVectors()
    {
        using var fixture = Fixtures();
        Equal("flac-metadata-v1", fixture.RootElement.GetProperty("schema").GetString());
        var vectors = fixture.RootElement.GetProperty("vectors");
        Equal(93, vectors.GetArrayLength());
        foreach (var vector in vectors.EnumerateArray())
        {
            string name = RequiredString(vector.GetProperty("name"));
            var bytes = Convert.FromBase64String(RequiredString(vector.GetProperty("dataBase64")));
            var reads = new List<(long Offset, int Count)>();
            Task<byte[]> Read(long offset, int count, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                Require(count is > 0 and <= AudioFlacFile.MaximumReadBytes && offset >= 0 && offset + count <= bytes.Length, name);
                reads.Add((offset, count));
                return Task.FromResult(bytes.AsSpan((int)offset, count).ToArray());
            }
            long size = vector.GetProperty("fileSize").GetInt64();
            if (vector.GetProperty("error").ValueKind != JsonValueKind.Null)
            {
                var reason = Enum.Parse<AudioFlacMetadataError>(RequiredString(vector.GetProperty("error")), true);
                var failure = await Throws<AudioFlacMetadataException>(() => AudioFlacFile.InspectAsync(size, Read, default));
                Equal(reason, failure.Reason, name);
                continue;
            }
            var actual = await AudioFlacFile.InspectAsync(size, Read, default);
            var expected = vector.GetProperty("expected");
            Equal(expected.GetProperty("sampleRate").GetUInt32(), actual.DecodedFormat.SampleRate, name);
            Equal(expected.GetProperty("channels").GetUInt16(), actual.DecodedFormat.Channels, name);
            Equal(expected.GetProperty("validBits").GetByte(), actual.DecodedFormat.ValidBits, name);
            Equal(expected.GetProperty("containerBits").GetByte(), actual.DecodedFormat.ContainerBits, name);
            Require(!actual.DecodedFormat.FloatingPoint, name);
            if (actual.DecodedFormat.ContainerBits == 8) Equal(AudioStreamingEncoding.Unsigned8, actual.DecodedFormat.Encoding, name);
            Equal<uint?>(expected.GetProperty("waveChannelMask").GetUInt32(), actual.DecodedFormat.WaveChannelMask, name);
            Equal(expected.GetProperty("hasExplicitChannelMask").GetBoolean(), actual.HasExplicitChannelMask, name);
            Equal(NullableLong(expected, "totalFrames"), actual.TotalFrames, name);
            Equal(expected.GetProperty("pcmMD5Hex").GetString(), actual.PcmMd5Hex, name);
            Equal(expected.GetProperty("firstFrameByteOffset").GetInt64(), actual.FirstFrameByteOffset, name);
            Equal(expected.GetProperty("minimumBlockFrames").GetUInt16(), actual.MinimumBlockFrames, name);
            Equal(expected.GetProperty("maximumBlockFrames").GetUInt16(), actual.MaximumBlockFrames, name);
            Equal((uint?)NullableLong(expected, "minimumFrameBytes"), actual.MinimumFrameBytes, name);
            Equal((uint?)NullableLong(expected, "maximumFrameBytes"), actual.MaximumFrameBytes, name);
            Require(reads.All(r => r.Offset + r.Count <= actual.FirstFrameByteOffset), name + " read audio bytes");
        }
    }

    private static async Task HeaderTruncations()
    {
        var source = Base();
        for (int count = 0; count <= 42; count++)
            Equal(AudioFlacMetadataError.Truncated, (await Throws<AudioFlacMetadataException>(
                () => Inspect(source.AsSpan(0, count).ToArray()))).Reason);
    }

    private static async Task CallbackFailures()
    {
        foreach (var (delta, reason) in new[] { (-1, AudioFlacMetadataError.Truncated), (1, AudioFlacMetadataError.InvalidReadLength) })
        {
            var error = await Throws<AudioFlacMetadataException>(() => AudioFlacFile.InspectAsync(43,
                (_, count, _) => Task.FromResult(new byte[count + delta]), default));
            Equal(reason, error.Reason);
        }
        var io = new IOException("source read failed");
        var actual = await Throws<IOException>(() => AudioFlacFile.InspectAsync(43,
            (_, _, _) => Task.FromException<byte[]>(io), default));
        Require(ReferenceEquals(io, actual), "Source exception was replaced");
    }

    private static async Task FileBounds()
    {
        foreach (long size in new[] { -1L, AudioFlacFile.MaximumFileBytes + 1 })
            Equal(AudioFlacMetadataError.Oversized, (await Throws<AudioFlacMetadataException>(() =>
                AudioFlacFile.InspectAsync(size, (_, _, _) => throw new InvalidOperationException("Unexpected read"), default))).Reason);
    }

    private static async Task CancellationChecks()
    {
        using var before = new CancellationTokenSource();
        before.Cancel();
        await Throws<OperationCanceledException>(() => AudioFlacFile.InspectAsync(43,
            (_, _, _) => throw new InvalidOperationException("Canceled source was read"), before.Token));
        using var during = new CancellationTokenSource();
        int reads = 0;
        await Throws<OperationCanceledException>(() => AudioFlacFile.InspectAsync(43, (_, _, _) =>
        {
            reads++;
            during.Cancel();
            return Task.FromResult("fLaC"u8.ToArray());
        }, during.Token));
        Equal(1, reads);
    }

    private static async Task CancellationWaitsForRead()
    {
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var read = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = AudioFlacFile.InspectAsync(43, (_, _, _) => { entered.SetResult(); return read.Task; }, cancellation.Token);
        await entered.Task;
        cancellation.Cancel();
        Require(!pending.IsCompleted, "Cancellation abandoned an in-flight source read");
        read.SetResult("fLaC"u8.ToArray());
        await Throws<OperationCanceledException>(() => pending);
    }

    private static async Task ResourceBounds()
    {
        var header = Base().AsSpan(0, 42).ToArray();
        header[4] = 0;
        byte[] many = [..header, ..Enumerable.Range(0, 4 * AudioFlacFile.MaximumBlocks).Select(i => (byte)(i % 4 == 0 ? 1 : 0)), 0xff];
        Equal(AudioFlacMetadataError.MetadataLimit, (await Throws<AudioFlacMetadataException>(() => Inspect(many))).Reason);
        int length = AudioFlacFile.MaximumCommentBytes + 1;
        byte[] prefix = [..header, 0x84, (byte)(length >> 16), (byte)(length >> 8), (byte)length];
        Equal(AudioFlacMetadataError.MetadataLimit, (await Throws<AudioFlacMetadataException>(() => AudioFlacFile.InspectAsync(
            prefix.Length + length + 1, (offset, count, _) =>
            {
                Require(offset + count <= prefix.Length, "Unbounded comment payload was read");
                return Task.FromResult(prefix.AsSpan((int)offset, count).ToArray());
            }, default))).Reason);
        int reads = 0;
        Equal(AudioFlacMetadataError.MetadataLimit, (await Throws<AudioFlacMetadataException>(() => AudioFlacFile.InspectAsync(
            100_000_000, (offset, count, _) =>
            {
                reads++;
                if (offset < header.Length) return Task.FromResult(header.AsSpan((int)offset, count).ToArray());
                Equal(0L, (offset - 42) % (0x00ff_ffffL + 4)); Equal(4, count);
                return Task.FromResult(new byte[] { 1, 0xff, 0xff, 0xff });
            }, default))).Reason);
        Equal(7, reads);
    }

    private static JsonDocument Fixtures() => JsonDocument.Parse(File.ReadAllBytes(
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "flac-metadata-v1-vectors.json")));
    private static byte[] Base()
    {
        using var fixture = Fixtures();
        var vector = fixture.RootElement.GetProperty("vectors").EnumerateArray().Single(
            v => v.GetProperty("name").GetString() == "precision-24-channels-2");
        return Convert.FromBase64String(RequiredString(vector.GetProperty("dataBase64")));
    }
    private static Task<AudioFlacMetadata> Inspect(byte[] bytes) => AudioFlacFile.InspectAsync(bytes.LongLength,
        (offset, count, _) => Task.FromResult(bytes.AsSpan((int)offset, count).ToArray()), default);
    private static string RequiredString(JsonElement value) => value.GetString() ?? throw new InvalidDataException("Fixture string missing");
    private static long? NullableLong(JsonElement parent, string name) => parent.GetProperty(name).ValueKind == JsonValueKind.Null ? null : parent.GetProperty(name).GetInt64();
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Equal<T>(T expected, T actual, string context = "") => Require(EqualityComparer<T>.Default.Equals(expected, actual), $"{context}: expected {expected}, got {actual}");
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T failure) { return failure; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}");
    }
}
