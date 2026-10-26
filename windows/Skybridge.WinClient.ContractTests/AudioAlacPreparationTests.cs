using System.Security.Cryptography;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.FileTransfer;

internal static class AudioAlacPreparationTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("ALAC full-file preparation checks cancellation and authority at every observed checkpoint", PreparationCheckpoints),
        ("ALAC preparation enforces its deadline and rejects a regressed clock", PreparationDeadline),
        ("ALAC preparation cancellation retains an active authorization callback until it returns", PendingPreparation),
        ("ALAC bounded reader spans packets and refuses incomplete or mismatched final receipts", ReadBoundaries),
        ("ALAC cached PCM and final receipts retain live ownership and reject reentrant closure", CachedOwnership)
    ];

    private static Task PreparationCheckpoints() => WithArtifact(async artifact =>
    {
        int observed = 0;
        var prepared = await AudioPreparedOriginalFile.PrepareAsync(artifact, () => observed++, default, TimeProvider.System);
        var metadata = await AudioAlacDecoderTests.Metadata(AudioAlacDecoderTests.Bytes());
        Require(prepared.Format == metadata.DecodedFormat && prepared.FrameCount == metadata.TotalFrames && observed > 20,
            "Preparation did not bind a complete ALAC source to its exact format and frame count.");
        var failure = new InvalidOperationException("controlled source ownership revoked");
        for (int cut = 1; cut <= observed; cut++)
        {
            int reached = 0;
            var actual = await Throws<InvalidOperationException>(() => AudioPreparedOriginalFile.PrepareAsync(artifact,
                () => { if (++reached == cut) throw failure; }, default, TimeProvider.System));
            Require(ReferenceEquals(actual, failure) && reached == cut, "Preparation replaced or ignored an authorization failure.");
            using var cancelled = new CancellationTokenSource(); reached = 0;
            await Throws<OperationCanceledException>(() => AudioPreparedOriginalFile.PrepareAsync(artifact,
                () => { if (++reached == cut) cancelled.Cancel(); }, cancelled.Token, TimeProvider.System));
            Require(reached == cut, "Preparation ignored cancellation after an authority callback.");
            Require(!artifact.IsReleased, "The prepass disposed the caller-owned verified file.");
        }
        Console.WriteLine("ALAC_PREPARATION_CHECKPOINTS " + observed);
    });

    private static Task PreparationDeadline() => WithArtifact(async artifact =>
    {
        foreach (var elapsed in new[] { AudioPreparedOriginalFile.MaximumPreparationTime, TimeSpan.FromTicks(-1) })
        {
            var clock = new AudioCaptureReceiveSessionTests.TestClock(); int checks = 0;
            await Throws<TimeoutException>(() => AudioPreparedOriginalFile.PrepareAsync(artifact,
                () => { if (++checks == 10) clock.Advance(elapsed); }, default, clock));
            Require(checks == 10 && !artifact.IsReleased, "Deadline failure escaped its preparation boundary.");
        }
    });

    private static Task PendingPreparation() => WithArtifact(async artifact =>
    {
        using var cancelled = new CancellationTokenSource(); using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var preparing = AudioPreparedOriginalFile.PrepareAsync(artifact,
            () => { entered.TrySetResult(); release.Wait(); }, cancelled.Token, TimeProvider.System);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10)); cancelled.Cancel();
            Require(!preparing.IsCompleted && !artifact.IsReleased, "Cancellation detached the actual preparation callback.");
        }
        finally { release.Set(); }
        await Throws<OperationCanceledException>(() => preparing);
    });

    private static Task ReadBoundaries() => WithArtifact(async artifact =>
    {
        var metadata = await AudioAlacDecoderTests.Metadata(AudioAlacDecoderTests.Bytes());
        var receipt = new AudioAlacDecodeReceipt((ulong)metadata.TotalFrames, (ulong)metadata.PacketCount, (ulong)metadata.EncodedAudioBytes);
        var pcm = AudioAlacDecoderTests.Bytes("48000-2-s24", ".pcm"); int frameBytes = (int)metadata.DecodedFormat.BytesPerFrame;
        using (var reader = AudioDecodedFileReadSession.Alac(artifact, metadata, receipt, () => { }))
        {
            await Throws<InvalidDataException>(() => reader.FinishAsync(default));
            foreach (var pair in new[] { (1L, frameBytes), (0L, 0), (0L, frameBytes - 1), (0L, 65_538), (0L, pcm.Length + frameBytes) })
                await Throws<InvalidDataException>(() => reader.ReadAsync(pair.Item1, pair.Item2, default));
            await Drain(reader, pcm, frameBytes);
            await reader.FinishAsync(default);
            await Throws<InvalidDataException>(() => reader.ReadAsync(pcm.Length, frameBytes, default));
            reader.Dispose(); await Throws<ObjectDisposedException>(() => reader.FinishAsync(default));
        }
        using (var wrong = AudioDecodedFileReadSession.Alac(artifact, metadata, receipt with { Packets = receipt.Packets + 1 }, () => { }))
        {
            await Drain(wrong, pcm, frameBytes);
            await Throws<InvalidDataException>(() => wrong.FinishAsync(default));
        }
        Require(!artifact.IsReleased, "The PCM adapter disposed the caller-owned verified artifact.");
    });

    private static Task CachedOwnership() => WithArtifact(async artifact =>
    {
        var metadata = await AudioAlacDecoderTests.Metadata(AudioAlacDecoderTests.Bytes());
        var receipt = new AudioAlacDecodeReceipt((ulong)metadata.TotalFrames, (ulong)metadata.PacketCount, (ulong)metadata.EncodedAudioBytes);
        int frameBytes = (int)metadata.DecodedFormat.BytesPerFrame;
        var pcm = AudioAlacDecoderTests.Bytes("48000-2-s24", ".pcm");
        var failure = new InvalidOperationException("controlled authority revoked"); bool revoked = false;
        using (var reader = AudioDecodedFileReadSession.Alac(artifact, metadata, receipt, () => { if (revoked) throw failure; }))
        {
            await Drain(reader, pcm, frameBytes); await reader.FinishAsync(default); revoked = true;
            Require(ReferenceEquals(failure, await Throws<InvalidOperationException>(() => reader.FinishAsync(default))),
                "Cached completion escaped authorization.");
        }
        AudioDecodedFileReadSession? closing = null; bool closeOnFinalCheck = false; int checks = 0;
        using (closing = AudioDecodedFileReadSession.Alac(artifact, metadata, receipt, () =>
        {
            if (closeOnFinalCheck && ++checks == 3) (closing ?? throw new Exception("Missing PCM owner.")).Dispose();
        }))
        {
            await closing.ReadAsync(0, frameBytes, default); // Retain part of a decoded packet.
            closeOnFinalCheck = true;
            await Throws<ObjectDisposedException>(() => closing.ReadAsync(frameBytes, frameBytes, default));
            Require(checks == 3, "Closure did not exercise the post-copy authority boundary.");
        }
    });

    private static async Task Drain(IAudioFilePcmReader reader, byte[] pcm, int frameBytes)
    {
        int[] sizes = [frameBytes, frameBytes * 11, 65_536 - 65_536 % frameBytes]; int offset = 0, index = 0;
        while (offset < pcm.Length)
        {
            int count = Math.Min(sizes[index++ % sizes.Length], pcm.Length - offset);
            var block = await reader.ReadAsync(offset, count, default);
            Require(block.Length == count && block.AsSpan().SequenceEqual(pcm.AsSpan(offset, count)),
                "Packet/block boundaries changed sample bytes.");
            offset += count;
        }
    }

    private static async Task WithArtifact(Func<AudioOriginalFileArtifact, Task> action)
    {
        var bytes = AudioAlacDecoderTests.Bytes(); var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var metadata = ClassicFileTransferWire.Authenticate(new ClassicFileMetadata(Guid.NewGuid().ToString("D"),
            "source.m4a", bytes.Length, Convert.ToHexStringLower(SHA256.HashData(bytes)), 65_536, 2), key);
        using var wire = new MemoryStream();
        for (int offset = 0, index = 0; offset < bytes.Length; offset += 65_536)
            await ClassicFileTransferFrames.WriteAsync(wire, ClassicFileFrameType.Chunk,
                ClassicFileTransferWire.Encode(ClassicFileTransferWire.SealChunk(index++, bytes.AsSpan(offset, Math.Min(65_536, bytes.Length - offset)), key)), default);
        await ClassicFileTransferFrames.WriteAsync(wire, ClassicFileFrameType.Complete, ReadOnlyMemory<byte>.Empty, default);
        wire.Position = 0;
        string root = Path.Combine(AppContext.BaseDirectory, "alac-preparation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await using var artifact = await AudioOriginalFileArtifact.ReceiveAsync(wire, metadata, key, root, () => { }, default);
            await action(artifact);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            Require(Directory.GetFiles(root).Length == 0, "Private artifact cleanup did not actually complete."); Directory.Delete(root);
        }
    }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
}
