using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioAlacDecoderTests
{
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "Fixtures", "alac-decoder-v1");
    internal static IEnumerable<(string Name, Func<Task> Run)> Cases
    {
        get
        {
            yield return ("ALAC original files and integer PCM match the independent shared manifest", Manifest);
            using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Root, "manifest.json")));
            foreach (var item in document.RootElement.GetProperty("cases").EnumerateArray())
            {
                var name = item.GetProperty("name").GetString() ?? throw new Exception("Missing ALAC fixture name");
                yield return ($"native ALAC preserves every source sample byte: {name}", () => Golden(name));
            }
            yield return ("native ALAC rejects corrupt final packets after a valid prefix", CorruptTail);
            yield return ("native ALAC requires packet frame counts from the container", WrongFrameCount);
            yield return ("ALAC source failures retain identity and terminate the owner", SourceFailures);
            yield return ("ALAC revocation at every observed managed/native checkpoint returns no frame", RevocationSweep);
            yield return ("ALAC cancellation at every observed managed/native checkpoint returns no frame", CancellationSweep);
            yield return ("ALAC deferred close covers every observed managed/native checkpoint", CloseSweep);
            yield return ("ALAC cancellation and close retain a noncooperative read until it returns", PendingRead);
            yield return ("ALAC rejects concurrent operations without poisoning an active read", ConcurrentRead);
            yield return ("ALAC cached completion still requires live ownership", CachedCompletion);
            yield return ("ALAC bounds every compressed packet read to 64 KiB", BoundedLargePacket);
        }
    }

    internal static byte[] Bytes(string name = "48000-2-s24", string extension = ".m4a") => File.ReadAllBytes(Path.Combine(Root, name + extension));
    internal static Task<AudioAlacMetadata> Metadata(byte[] source) => AudioAlacFile.InspectAsync(source.Length,
        (offset, count, token) => Read(source, offset, count, token), default);
    private static Task<byte[]> Read(byte[] source, long offset, int count, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Require(count is > 0 and <= 65_536 && offset >= 0 && offset <= source.Length && count <= source.Length - offset,
            "Decoder requested an unbounded or invalid source range");
        return Task.FromResult(source.AsSpan(checked((int)offset), count).ToArray());
    }
    private static Task Manifest()
    {
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Root, "manifest.json")));
        Equal("alac-decoder-v1", manifest.RootElement.GetProperty("schema").GetString());
        var cases = manifest.RootElement.GetProperty("cases"); Equal(24, cases.GetArrayLength());
        Equal(49, Directory.GetFiles(Root).Length);
        foreach (var item in cases.EnumerateArray())
        {
            string name = item.GetProperty("name").GetString() ?? throw new Exception("Missing fixture name");
            var source = Bytes(name); var pcm = Bytes(name, ".pcm");
            Equal(item.GetProperty("fileBytes").GetInt32(), source.Length);
            Equal(item.GetProperty("pcmBytes").GetInt32(), pcm.Length);
            Equal(item.GetProperty("encodedSha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(source)));
            Equal(item.GetProperty("pcmSha256").GetString(), Convert.ToHexStringLower(SHA256.HashData(pcm)));
        }
        return Task.CompletedTask;
    }
    private static async Task Golden(string name)
    {
        var source = Bytes(name); var expected = Bytes(name, ".pcm"); var metadata = await Metadata(source);
        int largestRead = 0; bool collected = false;
        using var decoder = new AudioAlacPcmDecoder((offset, count, token) =>
        {
            largestRead = Math.Max(largestRead, count);
            if (!collected) { collected = true; GC.Collect(); GC.WaitForPendingFinalizers(); }
            return Read(source, offset, count, token);
        }, metadata);
        int matched = 0;
        for (long packet = 0; packet < metadata.PacketCount; packet++)
        {
            var result = decoder.Next(() => { }, default);
            Require(result is AudioAlacDecodeStep.Frame, "Missing indexed ALAC frame");
            var frame = (AudioAlacDecodeStep.Frame)result;
            Equal((ulong)(matched / metadata.DecodedFormat.BytesPerFrame), frame.FirstIndex);
            Equal((long)frame.FrameCount * metadata.DecodedFormat.BytesPerFrame, (long)frame.Bytes.Length);
            Require(frame.Bytes.Length <= expected.Length - matched && frame.Bytes.AsSpan().SequenceEqual(expected.AsSpan(matched, frame.Bytes.Length)),
                "PCM differs from the independent integer reference");
            matched += frame.Bytes.Length;
        }
        Require(decoder.Next(() => { }, default) is AudioAlacDecodeStep.Complete complete &&
            complete.Receipt == new AudioAlacDecodeReceipt((ulong)metadata.TotalFrames, (ulong)metadata.PacketCount, (ulong)metadata.EncodedAudioBytes),
            "Completion lacks exact indexed source counts");
        Equal(expected.Length, matched); Require(largestRead is > 0 and <= 65_536);
    }
    private static async Task CorruptTail()
    {
        var source = Bytes(); var metadata = await Metadata(source); var cursor = metadata.MakePacketCursor();
        AudioAlacPacket? last = null;
        while (await cursor.NextAsync((o, c, t) => Read(source, o, c, t), () => { }, default) is { } packet) last = packet;
        var tail = last ?? throw new Exception("No ALAC fixture packet"); Require(tail.Index > 0);
        source.AsSpan((int)tail.ByteOffset, tail.ByteCount).Clear();
        using var decoder = Decoder(source, metadata);
        Require(decoder.Next(() => { }, default) is AudioAlacDecodeStep.Frame);
        var failure = Throws<AudioAlacDecodeException>(() => DecodeAll(decoder, metadata));
        Equal(AudioAlacDecoderStatus.CodecError, failure.Status);
        Require(ReferenceEquals(failure, Throws<AudioAlacDecodeException>(() => decoder.Next(() => { }, default))));
    }
    private static async Task WrongFrameCount()
    {
        var source = Bytes(); int stts = Payload(source, "stts"), mdhd = Payload(source, "mdhd");
        uint frames = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(stts + 12));
        uint total = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(mdhd + 16));
        BinaryPrimitives.WriteUInt32BigEndian(source.AsSpan(stts + 12), frames - 1);
        BinaryPrimitives.WriteUInt32BigEndian(source.AsSpan(mdhd + 16), total - 1);
        var metadata = await Metadata(source); using var decoder = Decoder(source, metadata);
        Equal(AudioAlacDecoderStatus.FrameCountMismatch, Throws<AudioAlacDecodeException>(() => DecodeAll(decoder, metadata)).Status);
    }
    private static async Task SourceFailures()
    {
        var source = Bytes(); var metadata = await Metadata(source); var cursor = metadata.MakePacketCursor();
        var packet = await cursor.NextAsync((o, c, t) => Read(source, o, c, t), () => { }, default) ?? throw new Exception("Missing packet");
        foreach (bool duringPayload in new[] { false, true })
        {
            var fault = new IOException("source lease lost");
            using var decoder = new AudioAlacPcmDecoder((offset, count, token) =>
            {
                if (!duringPayload || offset == packet.ByteOffset) throw fault;
                return Read(source, offset, count, token);
            }, metadata);
            Require(ReferenceEquals(fault, Throws<IOException>(() => decoder.Next(() => { }, default))));
            Require(ReferenceEquals(fault, Throws<IOException>(() => decoder.Next(() => { }, default))));
        }
        foreach (int delta in new[] { -1, 1 })
        {
            using var decoder = new AudioAlacPcmDecoder((offset, count, token) => offset == packet.ByteOffset
                ? Task.FromResult(new byte[count + delta]) : Read(source, offset, count, token), metadata);
            var fault = Throws<InvalidDataException>(() => decoder.Next(() => { }, default));
            Require(ReferenceEquals(fault, Throws<InvalidDataException>(() => decoder.Next(() => { }, default))));
        }
    }
    private static int CountCheckpoints(byte[] source, AudioAlacMetadata metadata)
    {
        using var decoder = Decoder(source, metadata); int count = 0;
        Require(decoder.Next(() => count++, default) is AudioAlacDecodeStep.Frame);
        Require(count > 0); return count;
    }
    private static async Task RevocationSweep()
    {
        var source = Bytes(); var metadata = await Metadata(source); int checkpoints = CountCheckpoints(source, metadata);
        for (int position = 1; position <= checkpoints; position++)
        {
            using var decoder = Decoder(source, metadata); int calls = 0; var fault = new IOException("authorization revoked");
            var failure = Throws<IOException>(() => decoder.Next(() => { if (++calls == position) throw fault; }, default));
            Require(ReferenceEquals(failure, fault));
            Require(ReferenceEquals(fault, Throws<IOException>(() => decoder.Next(() => { }, default))));
            Equal(position, calls);
        }
        Console.WriteLine($"  ALAC revocation checkpoints: {checkpoints}");
    }
    private static async Task CancellationSweep()
    {
        var source = Bytes(); var metadata = await Metadata(source); int checkpoints = CountCheckpoints(source, metadata);
        for (int position = 1; position <= checkpoints; position++)
        {
            using var token = new CancellationTokenSource(); using var decoder = Decoder(source, metadata); int calls = 0;
            var failure = Throws<OperationCanceledException>(() => decoder.Next(() => { if (++calls == position) token.Cancel(); }, token.Token));
            Equal(token.Token, failure.CancellationToken);
            Require(ReferenceEquals(failure, Throws<OperationCanceledException>(() => decoder.Next(() => { }, default))));
            Equal(position, calls);
        }
        Console.WriteLine($"  ALAC cancellation checkpoints: {checkpoints}");
    }
    private static async Task CloseSweep()
    {
        var source = Bytes(); var metadata = await Metadata(source); int checkpoints = CountCheckpoints(source, metadata);
        for (int position = 1; position <= checkpoints; position++)
        {
            using var decoder = Decoder(source, metadata); int calls = 0;
            Throws<ObjectDisposedException>(() => decoder.Next(() => { if (++calls == position) decoder.Dispose(); }, default));
            Throws<ObjectDisposedException>(() => decoder.Next(() => { }, default)); Equal(position, calls);
            decoder.Dispose();
        }
        Console.WriteLine($"  ALAC close checkpoints: {checkpoints}");
    }
    private static async Task PendingRead()
    {
        var source = Bytes(); var metadata = await Metadata(source);
        foreach (bool close in new[] { false, true })
        {
            using var cancellation = new CancellationTokenSource();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var decoder = new AudioAlacPcmDecoder(async (offset, count, _) =>
            { entered.TrySetResult(); await release.Task; return source.AsSpan((int)offset, count).ToArray(); }, metadata);
            var operation = Task.Run(() => decoder.Next(() => { }, cancellation.Token));
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                if (close) decoder.Dispose(); else cancellation.Cancel();
                await Task.Delay(30); Require(!operation.IsCompleted, "Owner released a pending source read");
            }
            finally { release.TrySetResult(); }
            if (close) await ThrowsAsync<ObjectDisposedException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
            else await ThrowsAsync<OperationCanceledException>(() => operation.WaitAsync(TimeSpan.FromSeconds(5)));
        }
    }
    private static async Task ConcurrentRead()
    {
        var source = Bytes(); var metadata = await Metadata(source);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var decoder = new AudioAlacPcmDecoder(async (offset, count, token) =>
        { entered.TrySetResult(); await release.Task; return await Read(source, offset, count, token); }, metadata);
        var operation = Task.Run(() => decoder.Next(() => { }, default));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Throws<InvalidOperationException>(() => decoder.Next(() => { }, default));
        }
        finally { release.TrySetResult(); }
        Require(await operation.WaitAsync(TimeSpan.FromSeconds(5)) is AudioAlacDecodeStep.Frame);
        Require(decoder.Next(() => { }, default) is AudioAlacDecodeStep.Frame);
        Require(decoder.Next(() => { }, default) is AudioAlacDecodeStep.Complete);
    }
    private static async Task CachedCompletion()
    {
        var source = Bytes(); var metadata = await Metadata(source); using var decoder = Decoder(source, metadata);
        var receipt = DecodeAll(decoder, metadata);
        Require(decoder.Next(() => { }, default) is AudioAlacDecodeStep.Complete again && again.Receipt == receipt);
        var fault = new IOException("completed source authorization was revoked");
        Require(ReferenceEquals(fault, Throws<IOException>(() => decoder.Next(() => throw fault, default))));
        Require(ReferenceEquals(fault, Throws<IOException>(() => decoder.Next(() => { }, default))));
    }
    private static async Task BoundedLargePacket()
    {
        var source = Bytes(); var metadata = await Metadata(source);
        var cursor = metadata.MakePacketCursor();
        var packet = await cursor.NextAsync((o, c, t) => Read(source, o, c, t), () => { }, default) ?? throw new Exception("Missing packet");
        const int length = 2 * 65_536 + 1;
        int originalSize = packet.ByteCount, extra = length - originalSize, at = (int)packet.ByteOffset;
        var expanded = new byte[source.Length + extra];
        source.AsSpan(0, at).CopyTo(expanded); source.AsSpan(at + originalSize).CopyTo(expanded.AsSpan(at + length));
        int mdat = Payload(expanded, "mdat") - 8;
        uint oldSize = BinaryPrimitives.ReadUInt32BigEndian(expanded.AsSpan(mdat));
        BinaryPrimitives.WriteUInt32BigEndian(expanded.AsSpan(mdat), oldSize + (uint)extra);
        BinaryPrimitives.WriteUInt32BigEndian(expanded.AsSpan(Payload(expanded, "stsz") + 12), length);
        // Maximum compressed packet bytes are opaque codec metadata, not a decoded sample conversion.
        int config = Payload(expanded, "alac", 1); BinaryPrimitives.WriteUInt32BigEndian(expanded.AsSpan(config + 16), length);
        var large = await Metadata(expanded); var chunks = new List<int>();
        using var decoder = new AudioAlacPcmDecoder((offset, count, token) =>
        {
            if (offset >= at && offset < at + length) chunks.Add(count);
            return Read(expanded, offset, count, token);
        }, large);
        var failure = Throws<AudioAlacDecodeException>(() => decoder.Next(() => { }, default));
        Equal(AudioAlacDecoderStatus.CodecError, failure.Status);
        Require(chunks.SequenceEqual(new[] { 65_536, 65_536, 1 }), "Compressed packet read exceeded the bounded I/O contract");
    }

    internal static Task Component(string state)
    {
        Equal(state != "absent", AudioAlacNative.IsPackaged);
        var error = Throws<AudioAlacComponentException>(AudioAlacNative.RequireCompatible);
        if (state == "absent") Require(error.InnerException is DllNotFoundException);
        else if (state == "invalid") Require(error.InnerException is DllNotFoundException or BadImageFormatException);
        else if (state == "old-abi") Require(error.InnerException is EntryPointNotFoundException);
        else if (state == "missing-decode") Require(error.InnerException is EntryPointNotFoundException missing &&
            missing.Message.Contains("sbalac_decoder_decode", StringComparison.Ordinal));
        else throw new Exception("Unknown isolated component case");
        Console.WriteLine("PASS ALAC component rejects " + state); return Task.CompletedTask;
    }
    private static AudioAlacPcmDecoder Decoder(byte[] source, AudioAlacMetadata metadata) => new((o, c, t) => Read(source, o, c, t), metadata);
    private static AudioAlacDecodeReceipt DecodeAll(AudioAlacPcmDecoder decoder, AudioAlacMetadata metadata)
    {
        for (long i = 0; i <= metadata.PacketCount; i++)
            if (decoder.Next(() => { }, default) is AudioAlacDecodeStep.Complete result) return result.Receipt;
        throw new Exception("ALAC decoder did not complete its bounded sequence");
    }
    private static int Payload(byte[] source, string name, int occurrence = 0)
    {
        int position = 0; var tag = System.Text.Encoding.ASCII.GetBytes(name);
        for (int i = 0; i <= occurrence; i++)
        {
            int found = source.AsSpan(position).IndexOf(tag); Require(found >= 0, "Missing fixture field " + name); position += found + 4;
        }
        return position;
    }
    private static T Throws<T>(Action run) where T : Exception
    { try { run(); } catch (T error) { return error; } throw new Exception("Expected " + typeof(T).Name); }
    private static async Task<T> ThrowsAsync<T>(Func<Task> run) where T : Exception
    { try { await run(); } catch (T error) { return error; } throw new Exception("Expected " + typeof(T).Name); }
    private static void Require(bool condition, string message = "Contract assertion failed") { if (!condition) throw new Exception(message); }
    private static void Equal<T>(T expected, T actual) => Require(EqualityComparer<T>.Default.Equals(expected, actual), $"{expected} != {actual}");
}
