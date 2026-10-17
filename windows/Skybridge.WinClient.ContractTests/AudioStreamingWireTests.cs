using System.Globalization;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class AudioStreamingWireTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        Case("audio wire matches 31 shared vectors in bytes and typed semantics", GoldenVectors),
        Case("audio wire rejects every truncation and trailing byte", Truncations),
        Case("audio wire rejects corrupt headers UUIDs formats and reasons", Corruption),
        Case("audio wire enforces signed counters file windows and message limits", Limits),
        Case("audio wire unknown layout cannot become a native default", LayoutBoundary),
        Case("audio wire owns decoded buffers and preserves low sample bits", ArrayOwnership),
        ..AudioOpusWireTests.Cases
    ];
    private static (string, Func<Task>) Case(string name, Action action) => (name, () => { action(); return Task.CompletedTask; });
    private static JsonDocument Fixture() => JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "audio-streaming-v1-vectors.json")));
    private static Guid StreamId => Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
    private static byte[] Hash => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static AudioStreamingPcmFormat Format => new(44100, 2, AudioStreamingEncoding.Signed24, 24, 3);

    private static void GoldenVectors()
    {
        using var document = Fixture(); var rows = document.RootElement.GetProperty("vectors");
        Equal(31, rows.GetArrayLength());
        foreach (var vector in rows.EnumerateArray())
        {
            var expected = Expected(vector);
            var bytes = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
            var actual = AudioStreamingWire.Decode(bytes);
            Equal(StreamId, actual.StreamId); Equal(expected.GetType(), actual.Body.GetType());
            // Array-valued records require content comparison, not record reference equality.
            switch (actual.Body, expected)
            {
                case (AudioStreamingBody.FileOffer a, AudioStreamingBody.FileOffer e):
                    Equal(e.TransferId, a.TransferId); Equal(e.Length, a.Length); Bytes(e.Sha256, a.Sha256); break;
                case (AudioStreamingBody.PcmData a, AudioStreamingBody.PcmData e):
                    Equal(e.ByteOffset, a.ByteOffset); Bytes(e.Bytes, a.Bytes); break;
                case (AudioStreamingBody.End a, AudioStreamingBody.End e):
                    Equal(e.TotalBytes, a.TotalBytes); Bytes(e.Sha256, a.Sha256); break;
                case (AudioStreamingBody.ContentVerified a, AudioStreamingBody.ContentVerified e):
                    Equal(e.TotalBytes, a.TotalBytes); Bytes(e.Sha256, a.Sha256); break;
                default: Equal(expected, actual.Body); break;
            }
            Bytes(bytes, AudioStreamingWire.Encode(new(StreamId, expected)));
            Bytes(bytes, AudioStreamingWire.Encode(actual));
        }
    }

    private static AudioStreamingBody Expected(JsonElement vector)
    {
        var e = vector.GetProperty("expected");
        long Count(string name) => long.Parse(e.GetProperty(name).GetString()!, CultureInfo.InvariantCulture);
        byte[] Digest() => Convert.FromHexString(e.GetProperty("sha256Hex").GetString()!);
        AudioStreamingPcmFormat Pcm() => new(e.GetProperty("sampleRate").GetUInt32(), e.GetProperty("channels").GetUInt16(),
            (AudioStreamingEncoding)e.GetProperty("encoding").GetByte(), e.GetProperty("validBits").GetByte(),
            e.GetProperty("waveChannelMask").ValueKind == JsonValueKind.Null ? null : e.GetProperty("waveChannelMask").GetUInt32());
        return vector.GetProperty("opcode").GetInt32() switch
        {
            1 => new AudioStreamingBody.FileOffer(e.GetProperty("transferId").GetGuid(), Count("length"), Digest()),
            2 => new AudioStreamingBody.CaptureOffer(Pcm()),
            3 => new AudioStreamingBody.Accept(e.GetProperty("receiveWindowBytes").GetUInt32()),
            4 => new AudioStreamingBody.PcmData(Count("byteOffset"), Convert.FromHexString(e.GetProperty("dataHex").GetString()!)),
            5 => new AudioStreamingBody.Credit(Count("retiredBytes")),
            6 => new AudioStreamingBody.End(Count("totalBytes"), Digest()),
            7 => new AudioStreamingBody.ContentVerified(Count("totalBytes"), Digest()),
            8 => new AudioStreamingBody.OutputReady(Pcm()),
            9 => new AudioStreamingBody.PlaybackComplete(Count("sourceFrames"), e.GetProperty("trailingPaddingFrames").GetUInt32()),
            10 => new AudioStreamingBody.Stop((AudioStreamingStopReason)e.GetProperty("reason").GetUInt16()),
            _ => throw new InvalidDataException("Unexpected fixture opcode.")
        };
    }

    private static void Truncations()
    {
        using var document = Fixture();
        foreach (var vector in document.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var bytes = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
            for (int size = 0; size < bytes.Length; size++) Reject(() => AudioStreamingWire.Decode(bytes.AsSpan(0, size)));
            Reject(() => AudioStreamingWire.Decode([..bytes, 0]));
            bytes[24] = 0xFF; Reject(() => AudioStreamingWire.Decode(bytes));
        }
    }

    private static void Corruption()
    {
        var bytes = AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.CaptureOffer(Format)));
        foreach (var (index, value) in new (int, byte)[] { (0, 0), (4, 2), (5, 0), (5, 16), (6, 1), (7, 1),
            (34, 0), (34, 8), (35, 0), (35, 25), (36, 2), (37, 1), (38, 1), (39, 1), (36, 0) })
        {
            var changed = bytes.ToArray(); changed[index] = value; Reject(() => AudioStreamingWire.Decode(changed));
        }
        var zero = bytes.ToArray(); zero.AsSpan(8, 16).Clear(); Reject(() => AudioStreamingWire.Decode(zero));
        var stop = AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.Stop(AudioStreamingStopReason.UserStopped)));
        foreach (var (index, value) in new (int, byte)[] { (28, 1), (29, 0), (29, 14), (30, 1), (31, 1) })
        {
            var changed = stop.ToArray(); changed[index] = value; Reject(() => AudioStreamingWire.Decode(changed));
        }
        var credit = AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.Credit(0)));
        credit[28] = 0x80; Reject(() => AudioStreamingWire.Decode(credit));
    }

    private static void Limits()
    {
        AudioStreamingBody[] invalid = [new AudioStreamingBody.FileOffer(Guid.Empty, 1, Hash),
            new AudioStreamingBody.FileOffer(StreamId, 0, Hash), new AudioStreamingBody.FileOffer(StreamId, AudioStreamingWire.MaximumFileBytes + 1, Hash),
            new AudioStreamingBody.Accept(AudioStreamingWire.MaximumReceiveWindowBytes + 1),
            new AudioStreamingBody.PcmData(0, []), new AudioStreamingBody.PcmData(-1, [1]),
            new AudioStreamingBody.PcmData(long.MaxValue, [1]), new AudioStreamingBody.Credit(-1),
            new AudioStreamingBody.End(-1, Hash), new AudioStreamingBody.ContentVerified(1, new byte[31]),
            new AudioStreamingBody.PlaybackComplete(long.MaxValue, 1), new AudioStreamingBody.Stop((AudioStreamingStopReason)14)];
        foreach (var body in invalid) Reject(() => AudioStreamingWire.Encode(new(StreamId, body)));
        Reject(() => AudioStreamingWire.Encode(new(Guid.Empty, new AudioStreamingBody.Credit(0))));
        var payload = new byte[AudioStreamingWire.MaximumPcmDataBytes]; Array.Fill(payload, (byte)0xA5);
        var bytes = AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.PcmData(0, payload)));
        Equal(AudioStreamingWire.MaximumMessageBytes, bytes.Length);
        Bytes(payload, ((AudioStreamingBody.PcmData)AudioStreamingWire.Decode(bytes).Body).Bytes);
        Reject(() => AudioStreamingWire.Decode([..bytes, 0]));
        Reject(() => AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.PcmData(0, [..payload, 0]))));
        Reject(() => new AudioStreamingPcmFormat(0, 2, AudioStreamingEncoding.Signed24, 24, 3));
        Reject(() => new AudioStreamingPcmFormat(uint.MaxValue, 2, AudioStreamingEncoding.Signed24, 24, 3));
        Reject(() => new AudioStreamingPcmFormat(1, ushort.MaxValue, AudioStreamingEncoding.Signed64, 64, 0));
        Reject(() => new AudioStreamingPcmFormat(48000, 2, AudioStreamingEncoding.Float32, 24, 3));
    }

    private static void LayoutBoundary()
    {
        var unknown = new AudioStreamingPcmFormat(48000, 2, AudioStreamingEncoding.Float32, 32, null);
        var direct = new AudioStreamingPcmFormat(48000, 2, AudioStreamingEncoding.Float32, 32, 0);
        Check(unknown != direct, "Unknown layout became DIRECTOUT.");
        Reject(() => unknown.RequireExactOutputFormat());
        Equal(0U, direct.RequireExactOutputFormat().ChannelMask);
        var wider = new AudioStreamingPcmFormat(96000, 2, AudioStreamingEncoding.Signed32, 24, 3).RequireExactOutputFormat();
        Equal((ushort)32, wider.ContainerBits); Equal((ushort)24, wider.ValidBits);
    }

    private static void ArrayOwnership()
    {
        var samples = Convert.FromHexString("000000800100C07FFFFF7F00000080000000FFFF123456ABCDEF");
        var saved = samples.ToArray();
        var encoded = AudioStreamingWire.Encode(new(StreamId, new AudioStreamingBody.PcmData(9007199254740993, samples)));
        samples.AsSpan().Clear();
        var decoded = (AudioStreamingBody.PcmData)AudioStreamingWire.Decode(encoded).Body;
        encoded.AsSpan().Clear(); Bytes(saved, decoded.Bytes); Equal(9007199254740993L, decoded.ByteOffset);
    }

    private static void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { return; }
        throw new InvalidOperationException("Malformed audio input was accepted.");
    }
    private static void Bytes(byte[] expected, byte[] actual) => Check(expected.SequenceEqual(actual), "Audio bytes differ.");
    private static void Equal<T>(T expected, T actual) => Check(EqualityComparer<T>.Default.Equals(expected, actual), $"Expected {expected}, got {actual}.");
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
