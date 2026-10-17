using System.Buffers.Binary;
using System.Text;
using Skybridge.WinClient.Services.Audio;

internal static class AudioWavePcmFileTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("wave parser preserves every legacy PCM and float representation", LegacyRepresentations),
        ("wave parser preserves declared precision and every explicit layout", ExtensibleLayouts),
        ("wave parser matches Apple integer and IEEE sample vectors without reading PCM", CrossPlatformSampleVectors),
        ("wave parser accepts legacy extensions and bounded extensible tails", FormatExtensions),
        ("wave parser handles data before fmt and nonzero odd chunk padding", ChunkOrderAndPadding),
        ("wave parser accepts an empty data chunk", EmptyData),
        ("wave parser rejects duplicate chunks and segmented audio after data", DuplicateAndSegmentedChunks),
        ("wave parser rejects truncated headers payloads padding and partial tails", TruncationAndTails),
        ("wave parser rejects unsupported containers and bytes beyond RIFF", ContainerBoundaries),
        ("wave parser rejects inconsistent rates alignment and precision", InvalidFormats),
        ("wave parser validates the entire extensible GUID and extension length", ExtensibleValidation),
        ("wave parser rejects oversized sources and unsigned chunk overflow without large reads", SizeBounds),
        ("wave parser skips sparse unknown payloads beyond two GiB", SparseUnknownChunk),
        ("wave parser reads only forty bytes of a huge fmt chunk", SparseFormatChunk),
        ("wave parser enforces the exact 4096 chunk limit", ChunkLimit),
        ("wave parser rejects short long and null callback results", ExactReadLength),
        ("wave parser preserves synchronous and asynchronous callback exceptions", CallbackFailures),
        ("wave parser checks cancellation before and after reads", CancellationChecks),
        ("wave parser retains a noncooperative read until actual completion", CancellationWaitsForRead)
    ];

    private static async Task LegacyRepresentations()
    {
        foreach (var (tag, bits, encoding) in new (ushort, ushort, AudioStreamingEncoding)[]
        {
            (1, 8, AudioStreamingEncoding.Unsigned8), (1, 16, AudioStreamingEncoding.Signed16),
            (1, 24, AudioStreamingEncoding.Signed24), (1, 32, AudioStreamingEncoding.Signed32),
            (1, 64, AudioStreamingEncoding.Signed64), (3, 32, AudioStreamingEncoding.Float32),
            (3, 64, AudioStreamingEncoding.Float64)
        })
        {
            var wave = Riff(("fmt ", Format(tag: tag, bits: bits)), ("data", new byte[bits / 8 * 4]));
            var reads = new List<(long Offset, int Count)>();
            var result = await Inspect(wave, reads);
            Equal(encoding, result.Format.Encoding); Equal((byte)bits, result.Format.ValidBits);
            Equal((uint)44100, result.Format.SampleRate); Equal((ushort)2, result.Format.Channels);
            Equal<uint?>(null, result.Format.WaveChannelMask);
            Equal(44L, result.PcmByteOffset); Equal((long)(bits / 8 * 4), result.PcmByteCount);
            Equal(2L, result.FrameCount);
            Require(reads.All(r => r.Count <= 40 && r.Offset + r.Count <= 44), "PCM payload was read.");
            var failure = Throws<InvalidDataException>(() => result.Format.RequireExactOutputFormat());
            Require(failure.Message.Contains("layout", StringComparison.OrdinalIgnoreCase), "Unknown layout was inferred.");
        }
    }

    private static async Task ExtensibleLayouts()
    {
        foreach (uint mask in new uint[] { 0, 1, 3, 7, 0x80000000, uint.MaxValue })
        {
            var result = await Inspect(Riff(("fmt ", Format(bits: 32, extensible: true, validBits: 24, mask: mask)),
                ("data", new byte[16])));
            Equal(AudioStreamingEncoding.Signed32, result.Format.Encoding);
            Equal((byte)24, result.Format.ValidBits); Equal<uint?>(mask, result.Format.WaveChannelMask);
            Equal(68L, result.PcmByteOffset); Equal(2L, result.FrameCount);
            ExactPcmFormat explicitFormat = result.Format.RequireExactOutputFormat();
            Equal(mask, explicitFormat.ChannelMask); Equal((ushort)24, explicitFormat.ValidBits);
            // Conversion to a descriptor is not an assertion that any endpoint supports this mask.
        }
        foreach (ushort bits in new ushort[] { 32, 64 })
        {
            var result = await Inspect(Riff(("fmt ", Format(tag: 3, bits: bits, extensible: true)),
                ("data", new byte[bits / 8 * 2])));
            Equal(bits == 32 ? AudioStreamingEncoding.Float32 : AudioStreamingEncoding.Float64, result.Format.Encoding);
            Equal((byte)bits, result.Format.ValidBits); Equal(1L, result.FrameCount);
        }
    }

    private static async Task CrossPlatformSampleVectors()
    {
        // Same sample vectors as Apple AudioWavePCMFileTests.testPreparedOutboundReaderReturnsOriginalIntegerAndFloatPayloadBytes.
        foreach (var (description, pcm, encoding, frames) in new (byte[], byte[], AudioStreamingEncoding, long)[]
        {
            (Format(bits: 24, extensible: true), Convert.FromHexString("FFFF7F000080010000FFFFFF"), AudioStreamingEncoding.Signed24, 2),
            (Format(tag: 3, bits: 64, extensible: true), Convert.FromHexString("452301000000F87F0000000000000080"), AudioStreamingEncoding.Float64, 1)
        })
        {
            var wave = Riff(("JUNK", [0xa1]), ("fmt ", description), ("data", pcm));
            var original = wave.ToArray();
            var reads = new List<(long Offset, int Count)>();
            var result = await Inspect(wave, reads);
            Equal(78L, result.PcmByteOffset); Equal((long)pcm.Length, result.PcmByteCount);
            Equal(frames, result.FrameCount); Equal(encoding, result.Format.Encoding);
            Bytes(original, wave); Bytes(pcm, wave.AsSpan(checked((int)result.PcmByteOffset), pcm.Length).ToArray());
            Require(reads.All(r => r.Offset + r.Count <= result.PcmByteOffset), "Sample bytes were inspected or normalized.");
        }
    }

    private static async Task FormatExtensions()
    {
        foreach (byte[] extra in new byte[][] { [], [0xff], [0xff, 0xff], [0xff, 0xff, 0xa5] })
        {
            var result = await Inspect(Riff(("fmt ", [..Format(), ..extra]), ("data", [])));
            Equal(AudioStreamingEncoding.Signed16, result.Format.Encoding);
        }
        var longer = Format(extensible: true, rate: 12345).Concat(new byte[4]).ToArray();
        Put16(longer, 16, 26);
        var reads = new List<(long Offset, int Count)>();
        var extended = await Inspect(Riff(("fmt ", longer), ("data", [])), reads);
        Equal((uint)12345, extended.Format.SampleRate);
        Require(reads.Any(r => r.Count == 40) && reads.All(r => r.Count <= 40), "fmt read was not bounded.");
    }

    private static async Task ChunkOrderAndPadding()
    {
        var wave = Riff(("data", [0, 128, 255]), ("JUNK", [1, 2, 3]),
            ("LIST", Encoding.ASCII.GetBytes("INFO")), ("fmt ", Format(bits: 8, channels: 1)));
        Equal((byte)0xa5, wave[23]);
        var result = await Inspect(wave);
        Equal(20L, result.PcmByteOffset); Equal(3L, result.PcmByteCount); Equal(3L, result.FrameCount);
        Bytes([0, 128, 255], wave.AsSpan(20, 3).ToArray());
    }

    private static async Task EmptyData()
    {
        var result = await Inspect(Riff(("fmt ", Format()), ("data", [])));
        Equal(44L, result.PcmByteOffset); Equal(0L, result.PcmByteCount); Equal(0L, result.FrameCount);
    }

    private static async Task DuplicateAndSegmentedChunks()
    {
        foreach (var trailing in new (string, byte[])[]
        {
            ("fmt ", Format()), ("data", []), ("LIST", Encoding.ASCII.GetBytes("wavl")), ("slnt", new byte[4])
        })
            await Reject(Riff(("fmt ", Format()), ("data", []), trailing), AudioWavePcmFileError.UnsupportedLayout);
        await Reject(Riff(("fmt ", Format()), ("data", []), ("LIST", [1, 2, 3])), AudioWavePcmFileError.Malformed);
        await Reject(Riff(("fmt ", Format())), AudioWavePcmFileError.Malformed);
        await Reject(Riff(("data", [])), AudioWavePcmFileError.Malformed);
        await Reject(Riff(), AudioWavePcmFileError.Malformed);
    }

    private static async Task TruncationAndTails()
    {
        var wave = Riff(("fmt ", Format(bits: 8, channels: 1)), ("data", [0x80]));
        for (int size = 0; size < wave.Length; size++)
            await Reject(wave.AsSpan(0, size).ToArray(), AudioWavePcmFileError.Truncated);
        var missingPad = wave.AsSpan(0, wave.Length - 1).ToArray();
        Put32(missingPad, 4, (uint)missingPad.Length - 8);
        await Reject(missingPad, AudioWavePcmFileError.Truncated);
        await Reject(Riff(("fmt ", new byte[15]), ("data", [])), AudioWavePcmFileError.Truncated);
        var partialTail = wave.Concat(new byte[] { 1, 2, 3 }).ToArray();
        Put32(partialTail, 4, (uint)partialTail.Length - 8);
        await Reject(partialTail, AudioWavePcmFileError.Truncated);
    }

    private static async Task ContainerBoundaries()
    {
        foreach (string magic in new[] { "RIFX", "RF64", "riff" })
        {
            var wave = Riff(("fmt ", Format()), ("data", []));
            Encoding.ASCII.GetBytes(magic).CopyTo(wave, 0);
            await Reject(wave, AudioWavePcmFileError.UnsupportedContainer);
        }
        var wrongType = Riff(("fmt ", Format()), ("data", []));
        wrongType[8] = 0;
        await Reject(wrongType, AudioWavePcmFileError.UnsupportedContainer);
        var outside = Riff(("fmt ", Format()), ("data", [])).Concat(new byte[] { 0 }).ToArray();
        await Reject(outside, AudioWavePcmFileError.UnsupportedLayout);
        var invalidSize = Header(12); Put32(invalidSize, 4, 3);
        await Reject(invalidSize, AudioWavePcmFileError.Malformed);
        foreach (var (tag, bits) in new (ushort, ushort)[] { (2, 16), (6, 16), (7, 16), (1, 20), (3, 16), (3, 24) })
            await Reject(Riff(("fmt ", Format(tag: tag, bits: bits)), ("data", [])), AudioWavePcmFileError.UnsupportedEncoding);
    }

    private static async Task InvalidFormats()
    {
        foreach (var mutate in new Action<byte[]>[]
        {
            f => Put16(f, 2, 0), f => Put32(f, 4, 0), f => Put32(f, 8, 0),
            f => Put32(f, 8, uint.MaxValue), f => Put16(f, 12, 3),
            f => Put32(f, 4, uint.MaxValue), f => { Put16(f, 2, ushort.MaxValue); Put16(f, 14, 64); }
        })
        {
            var format = Format(); mutate(format);
            await Reject(Riff(("fmt ", format), ("data", [])), AudioWavePcmFileError.Malformed);
        }
        await Reject(Riff(("fmt ", Format()), ("data", new byte[3])), AudioWavePcmFileError.Malformed);
        var edge = await Inspect(Riff(("fmt ", Format(bits: 8, channels: ushort.MaxValue, rate: 65537)), ("data", [])));
        Equal((uint)ushort.MaxValue, edge.Format.BytesPerFrame);
        Equal(uint.MaxValue, checked(edge.Format.SampleRate * edge.Format.BytesPerFrame));
    }

    private static async Task ExtensibleValidation()
    {
        await Reject(Riff(("fmt ", Format(extensible: true).AsSpan(0, 39).ToArray()), ("data", [])), AudioWavePcmFileError.Truncated);
        foreach (ushort extra in new ushort[] { 0, 21, 23, ushort.MaxValue })
        {
            var format = Format(extensible: true); Put16(format, 16, extra);
            await Reject(Riff(("fmt ", format), ("data", [])), AudioWavePcmFileError.Malformed);
        }
        await Reject(Riff(("fmt ", Format(bits: 32, extensible: true, validBits: 0)), ("data", [])), AudioWavePcmFileError.UndeclaredPrecision);
        await Reject(Riff(("fmt ", Format(bits: 32, extensible: true, validBits: 33)), ("data", [])), AudioWavePcmFileError.Malformed);
        await Reject(Riff(("fmt ", Format(tag: 3, bits: 32, extensible: true, validBits: 24)), ("data", [])), AudioWavePcmFileError.Malformed);
        for (int index = 28; index < 40; index++)
        {
            var format = Format(extensible: true); format[index] ^= 1;
            await Reject(Riff(("fmt ", format), ("data", [])), AudioWavePcmFileError.UnsupportedEncoding);
        }
        var wrongTag = Format(extensible: true); Put32(wrongTag, 24, 0x10001);
        await Reject(Riff(("fmt ", wrongTag), ("data", [])), AudioWavePcmFileError.UnsupportedEncoding);
    }

    private static async Task SizeBounds()
    {
        int reads = 0;
        Task<byte[]> Read(long offset, int count, CancellationToken token) { reads++; throw new InvalidOperationException("Unexpected read."); }
        foreach (long size in new[] { AudioWavePcmFile.MaximumFileBytes + 1, long.MaxValue })
        {
            var failure = await ThrowsAsync<AudioWavePcmFileException>(() => AudioWavePcmFile.InspectAsync(size, Read, default));
            Equal(AudioWavePcmFileError.Oversized, failure.Reason);
        }
        var negative = await ThrowsAsync<AudioWavePcmFileException>(() => AudioWavePcmFile.InspectAsync(-1, Read, default));
        Equal(AudioWavePcmFileError.Malformed, negative.Reason); Equal(0, reads);
        var bytes = Header(20).Concat(ChunkHeader("JUNK", uint.MaxValue)).ToArray();
        await Reject(bytes, AudioWavePcmFileError.Truncated);
    }

    private static async Task SparseUnknownChunk()
    {
        const uint hugeLength = 0x80000001;
        long tailOffset = 20L + hugeLength + 1;
        var tail = Chunk("fmt ", Format()).Concat(Chunk("data", new byte[4])).ToArray();
        long fileSize = tailOffset + tail.Length;
        var prefix = Header(fileSize).Concat(ChunkHeader("JUNK", hugeLength)).ToArray();
        var requests = new List<(long Offset, int Count)>();
        var result = await AudioWavePcmFile.InspectAsync(fileSize, (offset, count, token) =>
        {
            requests.Add((offset, count));
            if (offset < prefix.Length) return Task.FromResult(prefix.AsSpan(checked((int)offset), count).ToArray());
            Require(offset >= tailOffset, "Parser read the unknown payload.");
            return Task.FromResult(tail.AsSpan(checked((int)(offset - tailOffset)), count).ToArray());
        }, default);
        Equal(tailOffset + 32, result.PcmByteOffset); Equal(4L, result.PcmByteCount); Equal(1L, result.FrameCount);
        Equal(5, requests.Count); Require(requests.All(r => r.Count <= 40), "Unbounded read.");
    }

    private static async Task SparseFormatChunk()
    {
        const uint hugeLength = 0x80000000;
        long dataOffset = 20L + hugeLength;
        long fileSize = dataOffset + 8;
        var prefix = Header(fileSize).Concat(ChunkHeader("fmt ", hugeLength)).ToArray();
        var format = Format(extensible: true);
        var counts = new List<int>();
        var result = await AudioWavePcmFile.InspectAsync(fileSize, (offset, count, token) =>
        {
            counts.Add(count);
            if (offset < 20) return Task.FromResult(prefix.AsSpan(checked((int)offset), count).ToArray());
            if (offset == 20) { Equal(40, count); return Task.FromResult(format.ToArray()); }
            Equal(dataOffset, offset); Equal(8, count);
            return Task.FromResult(ChunkHeader("data", 0));
        }, default);
        Equal(fileSize, result.PcmByteOffset); Equal(0L, result.FrameCount);
        Require(counts.SequenceEqual(new[] { 12, 8, 40, 8 }), "Unexpected sparse fmt reads.");
    }

    private static async Task ChunkLimit()
    {
        var chunks = new List<(string, byte[])> { ("fmt ", Format()), ("data", []) };
        for (int index = 2; index < AudioWavePcmFile.MaximumChunks; index++) chunks.Add(("JUNK", []));
        Equal(0L, (await Inspect(Riff(chunks.ToArray()))).FrameCount);
        chunks.Add(("JUNK", []));
        await Reject(Riff(chunks.ToArray()), AudioWavePcmFileError.ChunkLimit);
    }

    private static async Task ExactReadLength()
    {
        var wave = Riff(("fmt ", Format()), ("data", []));
        foreach (int delta in new[] { -1, 1 })
        {
            int reads = 0;
            var failure = await ThrowsAsync<AudioWavePcmFileException>(() => AudioWavePcmFile.InspectAsync(wave.Length,
                (offset, count, token) => { reads++; return Task.FromResult(new byte[count + delta]); }, default));
            Equal(delta < 0 ? AudioWavePcmFileError.Truncated : AudioWavePcmFileError.InvalidReadLength, failure.Reason);
            Equal(1, reads);
        }
        var nullResult = await ThrowsAsync<AudioWavePcmFileException>(() => AudioWavePcmFile.InspectAsync(wave.Length,
            (offset, count, token) => Task.FromResult<byte[]>(null!), default));
        Equal(AudioWavePcmFileError.InvalidReadLength, nullResult.Reason);
    }

    private static async Task CallbackFailures()
    {
        var original = new IOException("Exact read failure.");
        var synchronous = await ThrowsAsync<IOException>(() => AudioWavePcmFile.InspectAsync(44,
            (offset, count, token) => throw original, default));
        Require(ReferenceEquals(original, synchronous), "Synchronous callback failure was replaced.");
        var asynchronous = await ThrowsAsync<IOException>(() => AudioWavePcmFile.InspectAsync(44,
            (offset, count, token) => Task.FromException<byte[]>(original), default));
        Require(ReferenceEquals(original, asynchronous), "Asynchronous callback failure was replaced.");
        using var cancellation = new CancellationTokenSource();
        var cancelledRead = await ThrowsAsync<IOException>(() => AudioWavePcmFile.InspectAsync(44,
            (offset, count, token) => { cancellation.Cancel(); return Task.FromException<byte[]>(original); }, cancellation.Token));
        Require(ReferenceEquals(original, cancelledRead), "Cancellation hid the actual callback failure.");
    }

    private static async Task CancellationChecks()
    {
        var wave = Riff(("fmt ", Format()), ("data", []));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel(); int reads = 0;
        var before = await ThrowsAsync<OperationCanceledException>(() => AudioWavePcmFile.InspectAsync(wave.Length,
            (offset, count, token) => { reads++; return Task.FromResult(new byte[count]); }, cancellation.Token));
        Equal(cancellation.Token, before.CancellationToken); Equal(0, reads);
        using var during = new CancellationTokenSource();
        var after = await ThrowsAsync<OperationCanceledException>(() => AudioWavePcmFile.InspectAsync(wave.Length,
            (offset, count, token) =>
            {
                Equal(during.Token, token); reads++; during.Cancel();
                return Task.FromResult(wave.AsSpan(checked((int)offset), count).ToArray());
            }, during.Token));
        Equal(during.Token, after.CancellationToken); Equal(1, reads);
    }

    private static async Task CancellationWaitsForRead()
    {
        var wave = Riff(("fmt ", Format()), ("data", []));
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var completion = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        int reads = 0;
        Task<byte[]> Read(long offset, int count, CancellationToken token)
        {
            Equal(cancellation.Token, token); Equal(0L, offset); Equal(12, count);
            reads++; entered.SetResult(true); return completion.Task;
        }
        var inspection = AudioWavePcmFile.InspectAsync(wave.Length, Read, cancellation.Token);
        await entered.Task;
        cancellation.Cancel();
        Require(!inspection.IsCompleted, "Parser abandoned the actual read on cancellation.");
        Equal(1, reads);
        completion.SetResult(wave.AsSpan(0, 12).ToArray());
        var failure = await ThrowsAsync<OperationCanceledException>(() => inspection);
        Equal(cancellation.Token, failure.CancellationToken); Equal(1, reads);
    }

    private static Task<AudioWavePcmMetadata> Inspect(byte[] bytes, List<(long Offset, int Count)>? reads = null) =>
        AudioWavePcmFile.InspectAsync(bytes.LongLength, (offset, count, token) =>
        {
            Require(count is > 0 and <= AudioWavePcmFile.MaximumReadBytes, "Invalid read bound.");
            Require(offset >= 0 && offset <= bytes.LongLength && count <= bytes.LongLength - offset, "Read outside source.");
            reads?.Add((offset, count));
            return Task.FromResult(bytes.AsSpan(checked((int)offset), count).ToArray());
        }, default);

    private static async Task Reject(byte[] bytes, AudioWavePcmFileError reason)
    {
        var failure = await ThrowsAsync<AudioWavePcmFileException>(() => Inspect(bytes));
        Equal(reason, failure.Reason);
    }

    private static byte[] Format(ushort tag = 1, ushort bits = 16, ushort channels = 2,
        uint rate = 44100, bool extensible = false, ushort? validBits = null, uint mask = 3)
    {
        var result = new byte[extensible ? 40 : 16];
        ushort alignment = checked((ushort)(channels * (bits / 8)));
        Put16(result, 0, extensible ? (ushort)0xfffe : tag); Put16(result, 2, channels);
        Put32(result, 4, rate); Put32(result, 8, checked(rate * alignment));
        Put16(result, 12, alignment); Put16(result, 14, bits);
        if (extensible)
        {
            Put16(result, 16, 22); Put16(result, 18, validBits ?? bits); Put32(result, 20, mask);
            Put32(result, 24, tag);
            new byte[] { 0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71 }.CopyTo(result, 28);
        }
        return result;
    }

    private static byte[] Riff(params (string Id, byte[] Bytes)[] chunks)
    {
        var payload = chunks.SelectMany(chunk => Chunk(chunk.Id, chunk.Bytes)).ToArray();
        return Header(payload.LongLength + 12).Concat(payload).ToArray();
    }

    private static byte[] Header(long fileSize)
    {
        var header = new byte[12];
        Encoding.ASCII.GetBytes("RIFF").CopyTo(header, 0);
        Put32(header, 4, checked((uint)(fileSize - 8)));
        Encoding.ASCII.GetBytes("WAVE").CopyTo(header, 8);
        return header;
    }

    private static byte[] ChunkHeader(string id, uint size)
    {
        var header = new byte[8]; Encoding.ASCII.GetBytes(id).CopyTo(header, 0); Put32(header, 4, size); return header;
    }

    private static byte[] Chunk(string id, byte[] bytes) =>
        [..ChunkHeader(id, checked((uint)bytes.Length)), ..bytes, ..(bytes.Length % 2 == 0 ? Array.Empty<byte>() : new byte[] { 0xa5 })];

    private static void Put16(byte[] bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), value);
    private static void Put32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
    private static void Bytes(byte[] expected, byte[] actual) => Require(expected.SequenceEqual(actual), "Byte sequences differ.");
    private static void Equal<T>(T expected, T actual) => Require(EqualityComparer<T>.Default.Equals(expected, actual), $"Expected {expected}; got {actual}.");
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static T Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T failure) { return failure; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    private static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T failure) { return failure; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
