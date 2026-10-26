using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioAlacFileTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("ALAC metadata and packets match 24 shared encoder fixtures without reading media", SharedVectors),
        ("ALAC rejects unsupported and inconsistent declarations", InvalidDeclarations),
        ("ALAC requires every structural prefix and media extent", Truncations),
        ("ALAC preserves I/O failures and exact callback lengths", CallbackFailures),
        ("ALAC cancellation surrounds the actual source read", Cancellation),
        ("ALAC retains noncooperative reads until completion", PendingRead),
        ("ALAC cached index and EOF require live ownership; failure is sticky", CachedOwnership),
        ("ALAC cursor rejects overlapping reads without poisoning the active read", OverlappingRead),
        ("ALAC rejects oversized sources and bounds box count", ResourceBounds),
        ("ALAC handles paged narrow/wide offsets and fixed/variable sizes with metadata at EOF", PagedTables),
        ("ALAC preserves distinct timing and chunk runs", DistinctRuns),
        ("ALAC supports unambiguous explicit channel layouts and open-ended media", Layouts)
    ];

    private static async Task SharedVectors()
    {
        var vectors = Vectors(); Equal(24, vectors.Length);
        using var packetsFile = Fixture("alac-packet-index-v1");
        var packetVectors = packetsFile.RootElement.GetProperty("vectors").EnumerateArray()
            .ToDictionary(x => Text(x, "name"), x => x);
        Equal(24, packetVectors.Count);
        foreach (var vector in vectors)
        {
            var metadata = await AudioAlacFile.InspectAsync(vector.Size, vector.Read, default);
            var expected = vector.Expected;
            Equal(expected.GetProperty("rate").GetUInt32(), metadata.DecodedFormat.SampleRate, vector.Name);
            Equal(expected.GetProperty("channels").GetUInt16(), metadata.DecodedFormat.Channels, vector.Name);
            byte bits = expected.GetProperty("validBits").GetByte(); Equal(bits, metadata.DecodedFormat.ValidBits, vector.Name);
            Equal((byte)(bits == 20 ? 24 : bits), metadata.DecodedFormat.ContainerBits, vector.Name);
            Equal(expected.GetProperty("frames").GetInt64(), metadata.TotalFrames, vector.Name);
            Equal(24, metadata.Configuration.Length);
            var packetVector = packetVectors[vector.Name]; Equal(vector.Hash, Text(packetVector, "sourceSha256"));
            var packets = packetVector.GetProperty("packets"); Equal((long)packets.GetArrayLength(), metadata.PacketCount);
            var cursor = metadata.MakePacketCursor(); long encoded = 0;
            foreach (var packet in packets.EnumerateArray())
            {
                var actual = await cursor.NextAsync(vector.Read, () => { }, default);
                Require(actual is not null, vector.Name);
                var expectedPacket = new AudioAlacPacket(packet.GetProperty("index").GetInt64(),
                    packet.GetProperty("firstFrameIndex").GetInt64(), packet.GetProperty("frames").GetUInt32(),
                    packet.GetProperty("offset").GetInt64(), packet.GetProperty("length").GetInt32());
                Equal(expectedPacket, actual, vector.Name); encoded += expectedPacket.ByteCount;
            }
            Equal(encoded, metadata.EncodedAudioBytes);
            Equal<AudioAlacPacket?>(null, await cursor.NextAsync(vector.Read, () => { }, default));
        }
    }

    private static async Task InvalidDeclarations()
    {
        var original = Base().Materialize();
        (string, AudioAlacFileError, Action<byte[]>)[] changes =
        [
            ("missing ftyp", AudioAlacFileError.UnsupportedContainer, b => Tag(b,"ftyp","free")),
            ("missing movie", AudioAlacFileError.Malformed, b => Tag(b,"moov","free")),
            ("disabled track", AudioAlacFileError.UnsupportedLayout, b => Set(b,"tkhd",0,0)),
            ("multiple tracks", AudioAlacFileError.UnsupportedLayout, b => Tag(b,"udta","trak")),
            ("edit timeline", AudioAlacFileError.UnsupportedLayout, b => Tag(b,"tkhd","edts")),
            ("fragmented movie", AudioAlacFileError.UnsupportedLayout, b => Tag(b,"udta","mvex")),
            ("fragmented media", AudioAlacFileError.UnsupportedLayout, b => Tag(b,"ftyp","moof")),
            ("sample grouping", AudioAlacFileError.UnsupportedLayout, b => Tag(b,"stts","sgpd")),
            ("external URL", AudioAlacFileError.UnsupportedLayout, b => Set(b,"url ",0,0)),
            ("external URN", AudioAlacFileError.UnsupportedLayout, b => Tag(b,"url ","urn ")),
            ("extra reference", AudioAlacFileError.UnsupportedLayout, b => Set(b,"dref",4,2)),
            ("AAC", AudioAlacFileError.UnsupportedEncoding, b => Tag(b,"alac","mp4a")),
            ("encrypted sample", AudioAlacFileError.UnsupportedEncoding, b => Tag(b,"alac","enca")),
            ("extra description", AudioAlacFileError.UnsupportedLayout, b => Set(b,"stsd",4,2)),
            ("sample version", AudioAlacFileError.UnsupportedLayout, b => b[Payload(b,"alac")+9]=1),
            ("codec version", AudioAlacFileError.UnsupportedEncoding, b => b[Payload(b,"alac",1)+8]=1),
            ("unknown depth", AudioAlacFileError.UnsupportedEncoding, b => b[Payload(b,"alac",1)+9]=31),
            ("channel order", AudioAlacFileError.UnsupportedLayout, b => b[Payload(b,"alac",1)+13]=6),
            ("native frame bound", AudioAlacFileError.MetadataLimit, b => Set(b,"alac",4,65537,1)),
            ("packet byte bound", AudioAlacFileError.Malformed, b => Set(b,"alac",16,1,1)),
            ("empty time run", AudioAlacFileError.Malformed, b => Set(b,"stts",8,0)),
            ("tail frame mismatch", AudioAlacFileError.Malformed, b => Set(b,"stts",20,720)),
            ("packet count", AudioAlacFileError.Malformed, b => Set(b,"stsz",8,3)),
            ("zero packet bytes", AudioAlacFileError.Malformed, b => Set(b,"stsz",12,0)),
            ("offset before media", AudioAlacFileError.Malformed, b => Set(b,"stco",8,8)),
            ("offset past media", AudioAlacFileError.Malformed, b => Set(b,"stco",8,(uint)b.Length-1)),
            ("zero first chunk", AudioAlacFileError.Malformed, b => Set(b,"stsc",8,0)),
            ("extra chunk packets", AudioAlacFileError.Malformed, b => Set(b,"stsc",12,3)),
            ("wrong description", AudioAlacFileError.Malformed, b => Set(b,"stsc",16,2)),
            ("wide table wrong size", AudioAlacFileError.Malformed, b => Tag(b,"stco","co64"))
        ];
        foreach (var (name, error, change) in changes)
        {
            var data = original.ToArray(); change(data);
            Equal(error, (await Throws<AudioAlacFileException>(() => Inspect(data))).Reason, name);
        }
    }

    private static async Task Truncations()
    {
        var data = Base().Materialize(); int media = Payload(data, "mdat");
        for (int length = 0; length < media; length++)
            await Throws<AudioAlacFileException>(() => Inspect(data[..length]));
        Equal(AudioAlacFileError.Truncated, (await Throws<AudioAlacFileException>(() => Inspect(data[..^1]))).Reason);
    }

    private static async Task CallbackFailures()
    {
        var vector = Base(); var failure = new IOException("source ownership lost");
        Require(ReferenceEquals(failure, await Throws<IOException>(() => AudioAlacFile.InspectAsync(vector.Size,
            (_, _, _) => throw failure, default))));
        foreach (int delta in new[] { -1, 1 })
        {
            var actual = await Throws<AudioAlacFileException>(() => AudioAlacFile.InspectAsync(vector.Size,
                (_, count, _) => Task.FromResult(new byte[count + delta]), default));
            Equal(delta < 0 ? AudioAlacFileError.Truncated : AudioAlacFileError.InvalidReadLength, actual.Reason);
        }
        var metadata = await AudioAlacFile.InspectAsync(vector.Size, vector.Read, default);
        var cursor = metadata.MakePacketCursor();
        Require(ReferenceEquals(failure, await Throws<IOException>(() => cursor.NextAsync((_, _, _) => throw failure, () => { }, default))));
        Require(ReferenceEquals(failure, await Throws<IOException>(() => cursor.NextAsync(vector.Read, () => { }, default))));
        foreach (int delta in new[] { -1, 1 })
        {
            var invalid = metadata.MakePacketCursor();
            var actual = await Throws<AudioAlacFileException>(() => invalid.NextAsync(
                (_, count, _) => Task.FromResult(new byte[count + delta]), () => { }, default));
            Equal(delta < 0 ? AudioAlacFileError.Truncated : AudioAlacFileError.InvalidReadLength, actual.Reason);
            Require(ReferenceEquals(actual, await Throws<AudioAlacFileException>(() => invalid.NextAsync(vector.Read, () => { }, default))));
        }
    }

    private static async Task Cancellation()
    {
        var vector = Base(); using var already = new CancellationTokenSource(); already.Cancel();
        await Throws<OperationCanceledException>(() => AudioAlacFile.InspectAsync(vector.Size,
            (_, _, _) => throw new Exception("Unexpected source read"), already.Token));
        using var during = new CancellationTokenSource();
        await Throws<OperationCanceledException>(() => AudioAlacFile.InspectAsync(vector.Size, (_, count, _) =>
        { during.Cancel(); return Task.FromResult(new byte[count]); }, during.Token));
        var metadata = await AudioAlacFile.InspectAsync(vector.Size, vector.Read, default);
        var cursor = metadata.MakePacketCursor();
        Require(await cursor.NextAsync(vector.Read, () => { }, default) is not null);
        var failure = await Throws<OperationCanceledException>(() => cursor.NextAsync(vector.Read, () => { }, already.Token));
        Require(ReferenceEquals(failure, await Throws<OperationCanceledException>(() => cursor.NextAsync(vector.Read, () => { }, default))));
    }

    private static async Task PendingRead()
    {
        using var cancel = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = AudioAlacFile.InspectAsync(Base().Size, (_, _, _) => { entered.SetResult(); return release.Task; }, cancel.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancel.Cancel();
        try { await Task.Delay(30); Require(!pending.IsCompleted, "Canceled while source read still owns its resources"); }
        finally { release.SetResult(new byte[8]); }
        await Throws<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    private static async Task CachedOwnership()
    {
        var vector = Base(); var metadata = await AudioAlacFile.InspectAsync(vector.Size, vector.Read, default);
        var cursor = metadata.MakePacketCursor(); Require(await cursor.NextAsync(vector.Read, () => { }, default) is not null);
        var failure = new IOException("revoked");
        Require(ReferenceEquals(failure, await Throws<IOException>(() => cursor.NextAsync(
            (_, _, _) => throw new Exception("Unexpected uncached read"), () => throw failure, default))));
        Require(ReferenceEquals(failure, await Throws<IOException>(() => cursor.NextAsync(vector.Read, () => { }, default))));
        var complete = metadata.MakePacketCursor();
        while (await complete.NextAsync(vector.Read, () => { }, default) is not null) { }
        Require(ReferenceEquals(failure, await Throws<IOException>(() => complete.NextAsync(vector.Read, () => throw failure, default))));
    }

    private static async Task OverlappingRead()
    {
        var vector = Base(); var metadata = await AudioAlacFile.InspectAsync(vector.Size, vector.Read, default);
        var cursor = metadata.MakePacketCursor();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<byte[]> Read(long offset, int count, CancellationToken token)
        { entered.TrySetResult(); await release.Task; return await vector.Read(offset, count, token); }
        var pending = cursor.NextAsync(Read, () => { }, default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        try { await Throws<InvalidOperationException>(() => cursor.NextAsync(vector.Read, () => { }, default)); }
        finally { release.SetResult(); }
        Equal(0L, (await pending.WaitAsync(TimeSpan.FromSeconds(5)))?.Index);
        Equal(1L, (await cursor.NextAsync(vector.Read, () => { }, default))?.Index);
    }

    private static async Task ResourceBounds()
    {
        foreach (long size in new[] { -1L, AudioAlacFile.MaximumFileBytes + 1 })
            Equal(AudioAlacFileError.Oversized, (await Throws<AudioAlacFileException>(() => AudioAlacFile.InspectAsync(size,
                (_, _, _) => throw new Exception("Unexpected oversized read"), default))).Reason);
        var data = Join(Enumerable.Range(0, AudioAlacFile.MaximumBoxes + 1).Select(_ => Box("free", [])).ToArray()); int reads = 0;
        var failure = await Throws<AudioAlacFileException>(() => AudioAlacFile.InspectAsync(data.Length,
            (offset, count, token) => { reads++; return Read(data, offset, count, token); }, default));
        Equal(AudioAlacFileError.MetadataLimit, failure.Reason); Equal(AudioAlacFile.MaximumBoxes, reads);
    }

    private static async Task PagedTables()
    {
        foreach (bool wide in new[] { false, true }) foreach (bool fixedBytes in new[] { false, true })
        {
            var file = Synthetic(Enumerable.Repeat(1u, 17003).ToArray(), Enumerable.Repeat(1u, 17003).ToArray(),
                Enumerable.Repeat(1, 17003).ToArray(), wide, fixedBytes);
            int largest = 0;
            Task<byte[]> MetadataRead(long offset, int count, CancellationToken token)
            {
                Require(offset + count <= file.MediaStart || offset >= file.MediaEnd, "Read encoded media during metadata inspection");
                largest = Math.Max(largest, count); return Read(file.Bytes, offset, count, token);
            }
            var metadata = await AudioAlacFile.InspectAsync(file.Bytes.Length, MetadataRead, default);
            var cursor = metadata.MakePacketCursor();
            foreach (var packet in file.Packets) Equal(packet, await cursor.NextAsync(MetadataRead, () => { }, default));
            Equal<AudioAlacPacket?>(null, await cursor.NextAsync(MetadataRead, () => { }, default));
            Equal(AudioAlacFile.MaximumReadBytes, largest);
        }
    }

    private static async Task DistinctRuns()
    {
        var file = Synthetic([1, 2, 2, 3, 3], [1, 2, 3, 4, 5], [2, 3]);
        var metadata = await Inspect(file.Bytes); Equal(11L, metadata.TotalFrames);
        var cursor = metadata.MakePacketCursor();
        foreach (var packet in file.Packets)
            Equal(packet, await cursor.NextAsync((o, c, t) => Read(file.Bytes, o, c, t), () => { }, default));
        Equal<AudioAlacPacket?>(null, await cursor.NextAsync((o, c, t) => Read(file.Bytes, o, c, t), () => { }, default));
    }

    private static async Task Layouts()
    {
        foreach (int layout in new[] { 1, 2 })
        {
            var file = Synthetic([1, 1], [1, 1], [1, 1], layout: layout);
            Equal(3u, (await Inspect(file.Bytes)).DecodedFormat.WaveChannelMask);
            Set(file.Bytes, "chan", 4, 0);
            Equal(AudioAlacFileError.UnsupportedLayout, (await Throws<AudioAlacFileException>(() => Inspect(file.Bytes))).Reason);
        }
        var bytes = Base().Materialize(); Put(bytes, Payload(bytes, "mdat") - 8, 0); Set(bytes, "alac", 16, 0, 1);
        Equal<uint?>(null, (await Inspect(bytes)).MaximumPacketBytes);
    }

    private sealed record Vector(string Name, long Size, string Hash, JsonElement Expected, (long Offset, byte[] Bytes)[] Ranges)
    {
        internal Task<byte[]> Read(long offset, int count, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Require(count is > 0 and <= AudioAlacFile.MaximumReadBytes);
            foreach (var range in Ranges)
                if (offset >= range.Offset && offset + count <= range.Offset + range.Bytes.Length)
                    return Task.FromResult(range.Bytes.AsSpan((int)(offset - range.Offset), count).ToArray());
            throw new Exception($"{Name}: unexpected media read {offset}+{count}");
        }
        // Only malformed-container tests materialize the sparse metadata; media is synthetic zero data.
        internal byte[] Materialize()
        {
            var data = new byte[checked((int)Size)];
            foreach (var range in Ranges) range.Bytes.CopyTo(data, checked((int)range.Offset));
            return data;
        }
    }
    private static Vector[] Vectors()
    {
        using var file = Fixture("alac-m4a-metadata-v1");
        return file.RootElement.GetProperty("vectors").EnumerateArray().Select(v => new Vector(Text(v, "name"),
            v.GetProperty("fileSize").GetInt64(), Text(v, "sourceSha256"), v.GetProperty("expected").Clone(),
            v.GetProperty("ranges").EnumerateArray().Select(r => (r.GetProperty("offset").GetInt64(),
                Convert.FromBase64String(Text(r, "bytes")))).ToArray())).ToArray();
    }
    private static Vector Base() => Vectors().Single(x => x.Name == "48000-2-s24");
    private static JsonDocument Fixture(string name)
    {
        var value = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name + ".json")));
        Equal(name, Text(value.RootElement, "schema")); return value;
    }
    private static string Text(JsonElement value, string key) => value.GetProperty(key).GetString() ?? throw new Exception("Invalid fixture string");
    private static Task<AudioAlacMetadata> Inspect(byte[] bytes) => AudioAlacFile.InspectAsync(bytes.Length, (o, c, t) => Read(bytes, o, c, t), default);
    private static Task<byte[]> Read(byte[] bytes, long offset, int count, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Require(offset >= 0 && count >= 0 && offset + count <= bytes.Length);
        return Task.FromResult(bytes.AsSpan((int)offset, count).ToArray());
    }
    private static int Payload(byte[] bytes, string name, int occurrence = 0)
    {
        int position = 0;
        for (int i = 0; i <= occurrence; i++)
        {
            int found = bytes.AsSpan(position).IndexOf(Encoding.ASCII.GetBytes(name)); Require(found >= 0, name);
            position += found + 4;
        }
        return position;
    }
    private static void Tag(byte[] bytes, string oldName, string newName) => Encoding.ASCII.GetBytes(newName).CopyTo(bytes, Payload(bytes, oldName) - 4);
    private static void Set(byte[] bytes, string name, int offset, uint value, int occurrence = 0) => Put(bytes, Payload(bytes, name, occurrence) + offset, value);
    private static void Put(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset, 4), value);
    private static byte[] Word(uint value) { var bytes = new byte[4]; Put(bytes, 0, value); return bytes; }
    private static byte[] LongWord(ulong value) => Join(Word((uint)(value >> 32)), Word((uint)value));
    private static byte[] Join(params byte[][] arrays)
    {
        var bytes = new byte[arrays.Sum(a => a.Length)]; int offset = 0;
        foreach (var array in arrays) { array.CopyTo(bytes, offset); offset += array.Length; }
        return bytes;
    }
    private static byte[] Box(string name, byte[] bytes) => Join(Word((uint)bytes.Length + 8), Encoding.ASCII.GetBytes(name), bytes);
    private sealed record SyntheticFile(byte[] Bytes, long MediaStart, long MediaEnd, AudioAlacPacket[] Packets);
    private static SyntheticFile Synthetic(uint[] frames, uint[] sizes, int[] groups, bool wide = false, bool fixedBytes = false, int layout = 0)
    {
        var ftyp = Box("ftyp", Join("M4A "u8.ToArray(), Word(0), "M4A "u8.ToArray()));
        int mediaBytes = checked((int)sizes.Sum(v => (long)v)); long mediaStart = ftyp.Length + (wide ? 16 : 8);
        var mdat = wide ? Join(Word(1), "mdat"u8.ToArray(), LongWord((ulong)mediaBytes + 16), new byte[mediaBytes]) : Box("mdat", new byte[mediaBytes]);
        var cookie = new byte[28]; Put(cookie, 4, frames.Max()); cookie[9] = 24; cookie[10] = 40; cookie[11] = 10;
        cookie[12] = 14; cookie[13] = 2; cookie[15] = 255; Put(cookie, 16, sizes.Max()); Put(cookie, 24, 48000);
        var chan = Box("chan", Join(Word(0), Word((101u << 16) + 2), Word(0), Word(0)));
        if (layout == 2) cookie = Join(cookie, chan);
        var audio = new byte[28]; audio[7] = 1; audio[17] = 2; audio[19] = 16; Put(audio, 24, 44100u << 16);
        audio = Join(audio, Box("alac", cookie), layout == 1 ? chan : []);
        var stsd = Box("stsd", Join(Word(0), Word(1), Box("alac", audio)));
        var times = new List<(uint Count, uint Delta)>();
        foreach (uint frame in frames)
        {
            if (times.Count > 0 && times[^1].Delta == frame) times[^1] = (times[^1].Count + 1, frame);
            else times.Add((1, frame));
        }
        var stts = Box("stts", Join(Word(0), Word((uint)times.Count), Join(times.Select(t => Join(Word(t.Count), Word(t.Delta))).ToArray())));
        var runs = new List<(uint First, uint Count)>(); var offsets = new List<byte[]>(); var packets = new List<AudioAlacPacket>();
        int packet = 0; long position = mediaStart, firstFrame = 0;
        for (int chunk = 0; chunk < groups.Length; chunk++)
        {
            uint count = (uint)groups[chunk];
            if (runs.Count == 0 || runs[^1].Count != count) runs.Add(((uint)chunk + 1, count));
            offsets.Add(wide ? LongWord((ulong)position) : Word((uint)position));
            for (int i = 0; i < count; i++)
            {
                packets.Add(new(packet, firstFrame, frames[packet], position, (int)sizes[packet]));
                position += sizes[packet]; firstFrame += frames[packet]; packet++;
            }
        }
        var stsc = Box("stsc", Join(Word(0), Word((uint)runs.Count), Join(runs.Select(r => Join(Word(r.First), Word(r.Count), Word(1))).ToArray())));
        var stsz = Box("stsz", Join(Word(0), Word(fixedBytes ? sizes[0] : 0), Word((uint)sizes.Length), fixedBytes ? [] : Join(sizes.Select(Word).ToArray())));
        var stco = Box(wide ? "co64" : "stco", Join(Word(0), Word((uint)groups.Length), Join(offsets.ToArray())));
        var dinf = Box("dinf", Box("dref", Join(Word(0), Word(1), Box("url ", Word(1)))));
        var minf = Box("minf", Join(dinf, Box("stbl", Join(stsd, stts, stsc, stsz, stco))));
        var mdhd = Box("mdhd", wide ? Join(Word(0x01000000), LongWord(0), LongWord(0), Word(48000), LongWord((ulong)firstFrame), Word(0))
            : Join(Word(0), Word(0), Word(0), Word(48000), Word((uint)firstFrame), Word(0)));
        var handler = Box("hdlr", Join(Word(0), Word(0), "soun"u8.ToArray(), new byte[12]));
        var trak = Box("trak", Join(Box("tkhd", Join(Word(1), new byte[80])), Box("mdia", Join(mdhd, handler, minf))));
        return new(Join(ftyp, mdat, Box("moov", trak)), mediaStart, mediaStart + mediaBytes, packets.ToArray());
    }
    private static void Require(bool condition, string message = "Contract assertion failed") { if (!condition) throw new Exception(message); }
    private static void Equal<T>(T expected, T actual, string message = "Contract mismatch") => Require(EqualityComparer<T>.Default.Equals(expected, actual), $"{message}: {expected} != {actual}");
    private static async Task<T> Throws<T>(Func<Task> run) where T : Exception
    {
        try { await run(); } catch (T error) { return error; }
        throw new Exception($"Expected {typeof(T).Name}");
    }
}
