using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioOpusWireTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        Case("Opus wire matches 21 independent typed vectors", Golden),
        Case("Opus wire rejects truncations trailing data and length changes", Truncations),
        Case("Opus wire rejects unsupported profile and reserved fields", Profile),
        Case("Opus wire rejects impossible counters and payload extents", Limits),
        Case("Opus wire owns payload arrays and cannot reuse strict source approval", Ownership)
    ];
    private static (string, Func<Task>) Case(string name, Action action) => (name, () => { action(); return Task.CompletedTask; });
    private static JsonDocument Fixture() => JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "audio-opus-v1-vectors.json")));
    private static Guid StreamId => Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static byte[] Digest => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static byte[] Vector(string name)
    {
        using var fixture = Fixture();
        return Convert.FromHexString(fixture.RootElement.GetProperty("vectors").EnumerateArray().Single(row => row.GetProperty("name").GetString() == name).GetProperty("hex").GetString()!);
    }

    private static void Golden()
    {
        using var fixture = Fixture(); var rows = fixture.RootElement.GetProperty("vectors"); Equal(21, rows.GetArrayLength());
        foreach (var row in rows.EnumerateArray())
        {
            var e = row.GetProperty("expected");
            long Number(string key) => long.Parse(e.GetProperty(key).GetString()!, CultureInfo.InvariantCulture);
            AudioStreamingBody expected = row.GetProperty("opcode").GetByte() switch
            {
                11 => new AudioStreamingBody.OpusOffer((AudioStreamingOpusSource)e.GetProperty("source").GetByte(),
                    new(e.GetProperty("channels").GetByte(), e.GetProperty("bitrate").GetUInt32())),
                12 => new AudioStreamingBody.OpusConfiguration(e.GetProperty("preSkipFrames").GetUInt16()),
                13 => new AudioStreamingBody.OpusData(Number("sequence"), Convert.FromHexString(e.GetProperty("dataHex").GetString()!)),
                14 => new AudioStreamingBody.OpusEnd(Number("sourceFrames"), Number("packetCount"), Number("totalEncodedBytes"),
                    Convert.FromHexString(e.GetProperty("sha256Hex").GetString()!)),
                15 => new AudioStreamingBody.OpusOutputReady(),
                _ => throw new InvalidDataException("Unknown Opus fixture opcode.")
            };
            var bytes = Convert.FromHexString(row.GetProperty("hex").GetString()!);
            var actual = AudioStreamingWire.Decode(bytes);
            Equal(StreamId, actual.StreamId); Equal(expected.GetType(), actual.Body.GetType());
            switch (actual.Body, expected)
            {
                case (AudioStreamingBody.OpusData a, AudioStreamingBody.OpusData b):
                    Equal(b.Sequence, a.Sequence); Bytes(b.Bytes, a.Bytes); break;
                case (AudioStreamingBody.OpusEnd a, AudioStreamingBody.OpusEnd b):
                    Equal(b.SourceFrames, a.SourceFrames); Equal(b.PacketCount, a.PacketCount);
                    Equal(b.TotalEncodedBytes, a.TotalEncodedBytes); Bytes(b.Sha256, a.Sha256); break;
                default: Equal(expected, actual.Body); break;
            }
            Bytes(bytes, AudioStreamingWire.Encode(new(StreamId, expected)));
            Bytes(bytes, AudioStreamingWire.Encode(actual));
        }
    }

    private static void Truncations()
    {
        using var fixture = Fixture();
        foreach (var row in fixture.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var bytes = Convert.FromHexString(row.GetProperty("hex").GetString()!);
            for (int size = 0; size < bytes.Length; size++) Reject(() => AudioStreamingWire.Decode(bytes.AsSpan(0, size)));
            Reject(() => AudioStreamingWire.Decode([.. bytes, 0]));
            byte[] longer = [.. bytes, 0]; BinaryPrimitives.WriteUInt32BigEndian(longer.AsSpan(24), (uint)(longer.Length - 28));
            Reject(() => AudioStreamingWire.Decode(longer));
            bytes[24] = 255; Reject(() => AudioStreamingWire.Decode(bytes));
        }
    }

    private static void Profile()
    {
        var offer = Vector("opus-offer-1-2-192000");
        foreach (var (index, value) in new (int, byte)[] { (28, 0), (28, 2), (29, 0), (29, 3), (30, 0), (30, 3),
            (31, 1), (32, 1), (37, 1), (38, 1), (39, 1), (40, 1) })
        {
            var changed = offer.ToArray(); changed[index] = value; Reject(() => AudioStreamingWire.Decode(changed));
        }
        foreach (byte channels in new byte[] { 0, 3 }) Reject(() => new AudioStreamingOpusFormat(channels, 192000));
        foreach (uint rate in new uint[] { 0, 64000, 192001 }) Reject(() => new AudioStreamingOpusFormat(2, rate));
        foreach (ushort skip in new ushort[] { 3841, ushort.MaxValue })
        {
            Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusConfiguration(skip))));
            var bytes = Vector("opus-configuration-312"); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(28), skip);
            Reject(() => AudioStreamingWire.Decode(bytes));
        }
        foreach (int index in new[] { 30, 31 })
        {
            var bytes = Vector("opus-configuration-312"); bytes[index] = 1; Reject(() => AudioStreamingWire.Decode(bytes));
        }
        Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusOffer((AudioStreamingOpusSource)3, new(2, 192000)))));
    }

    private static void Limits()
    {
        long maximum = AudioStreamingWire.MaximumOpusPacketCount;
        foreach (long sequence in new[] { -1L, maximum, long.MaxValue })
        {
            Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusData(sequence, new byte[320]))));
            var bytes = Vector("opus-data-320"); BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(28), sequence);
            Reject(() => AudioStreamingWire.Decode(bytes));
        }
        foreach (int length in new[] { 0, 319, 321, 479, 481, 639, 641, 4096 })
            Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusData(0, new byte[length]))));
        foreach (var (frames, count, total) in new (long, long, long)[] { (0, 1, 320), (-1, 1, 320), (long.MaxValue, 1, 320),
            (1, 0, 320), (1, -1, 320), (1, maximum + 1, 320), (1, 2, 641), (1, 2, 0), (1, 2, 1282) })
        {
            Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusEnd(frames, count, total, Digest))));
            var bytes = Vector("opus-end-short"); BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(28), frames);
            BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(36), count); BinaryPrimitives.WriteInt64BigEndian(bytes.AsSpan(44), total);
            Reject(() => AudioStreamingWire.Decode(bytes));
        }
        Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusEnd(1, 1, 320, new byte[31]))));
        Reject(() => AudioStreamingWire.Encode(new(Guid.Empty, new AudioStreamingBody.OpusOutputReady())));
    }

    private static void Ownership()
    {
        var original = Enumerable.Range(0, 640).Select(i => (byte)i).ToArray(); var saved = original.ToArray();
        var encoded = AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.OpusData(1, original)));
        original.AsSpan().Clear();
        var decoded = (AudioStreamingBody.OpusData)AudioStreamingWire.Decode(encoded).Body;
        encoded.AsSpan().Clear(); Bytes(saved, decoded.Bytes);
        var offer = AudioStreamingWire.Decode(Vector("opus-offer-1-2-192000"));
        Reject(() => AudioPlaybackSource.FromOffer(offer));
    }

    private static void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Malformed or unadmitted Opus input was accepted.");
    }
    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"Expected {expected}, got {actual}.");
    }
    private static void Bytes(byte[] expected, byte[] actual)
    {
        if (!expected.SequenceEqual(actual)) throw new InvalidOperationException("Opus bytes differ.");
    }
}
