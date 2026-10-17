using System.Buffers.Binary;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioStreamingEncoding : byte { Unsigned8 = 1, Signed16, Signed24, Signed32, Signed64, Float32, Float64 }
internal enum AudioStreamingStopReason : ushort
{
    UserStopped = 1, PermissionRevoked, SourceFailed, UnsupportedOutput, QueueOverflow,
    OutputLost, ProtocolViolation, AccountRevoked, SessionReplaced, TimedOut,
    ContentMismatch, UnsupportedSource, ReceiverDeclined
}

// Source metadata can have an unknown layout. A native output format cannot.
internal sealed record AudioStreamingPcmFormat
{
    public uint SampleRate { get; }
    public ushort Channels { get; }
    public AudioStreamingEncoding Encoding { get; }
    public byte ValidBits { get; }
    public uint? WaveChannelMask { get; }
    public byte ContainerBits => Encoding switch
    {
        AudioStreamingEncoding.Unsigned8 => 8, AudioStreamingEncoding.Signed16 => 16,
        AudioStreamingEncoding.Signed24 => 24, AudioStreamingEncoding.Signed32 or AudioStreamingEncoding.Float32 => 32,
        AudioStreamingEncoding.Signed64 or AudioStreamingEncoding.Float64 => 64,
        _ => throw new InvalidDataException("Unknown PCM encoding.")
    };
    public bool FloatingPoint => Encoding is AudioStreamingEncoding.Float32 or AudioStreamingEncoding.Float64;
    public uint BytesPerFrame => (uint)Channels * (uint)(ContainerBits / 8);

    public AudioStreamingPcmFormat(uint sampleRate, ushort channels, AudioStreamingEncoding encoding,
        byte validBits, uint? waveChannelMask)
    {
        SampleRate = sampleRate; Channels = channels; Encoding = encoding;
        ValidBits = validBits; WaveChannelMask = waveChannelMask;
        if (sampleRate == 0 || channels == 0 || validBits == 0 || validBits > ContainerBits ||
            (FloatingPoint && validBits != ContainerBits) || BytesPerFrame > ushort.MaxValue ||
            (ulong)sampleRate * BytesPerFrame > uint.MaxValue)
            throw new InvalidDataException("Invalid PCM representation.");
    }

    public ExactPcmFormat RequireExactOutputFormat() => new(SampleRate, Channels, ContainerBits,
        ValidBits, FloatingPoint, WaveChannelMask ?? throw new InvalidDataException("Output layout is unknown."));
}

internal enum AudioStreamingOpusSource : byte { OriginalFile = 1, SystemCapture = 2 }

// Explicit lossy Bluetooth profile, not original-file PCM or proof of physical output format.
internal sealed record AudioStreamingOpusFormat
{
    public byte Channels { get; }
    public uint Bitrate { get; }
    public uint SampleRate => 48000;
    public ushort PacketFrames => 960;
    public uint PacketBytes => Bitrate / 400;
    public AudioStreamingOpusFormat(byte channels, uint bitrate)
    {
        if (channels is not (1 or 2) || bitrate is not (128000 or 192000 or 256000))
            throw new InvalidDataException("Unsupported Opus profile.");
        Channels = channels; Bitrate = bitrate;
    }
}

internal abstract record AudioStreamingBody
{
    internal sealed record FileOffer(Guid TransferId, long Length, byte[] Sha256) : AudioStreamingBody;
    internal sealed record CaptureOffer(AudioStreamingPcmFormat Format) : AudioStreamingBody;
    internal sealed record Accept(uint ReceiveWindowBytes) : AudioStreamingBody;
    internal sealed record PcmData(long ByteOffset, byte[] Bytes) : AudioStreamingBody;
    internal sealed record Credit(long RetiredBytes) : AudioStreamingBody;
    internal sealed record End(long TotalBytes, byte[] Sha256) : AudioStreamingBody;
    internal sealed record ContentVerified(long TotalBytes, byte[] Sha256) : AudioStreamingBody;
    internal sealed record OutputReady(AudioStreamingPcmFormat Format) : AudioStreamingBody;
    internal sealed record PlaybackComplete(long SourceFrames, uint TrailingPaddingFrames) : AudioStreamingBody;
    internal sealed record Stop(AudioStreamingStopReason Reason) : AudioStreamingBody;
    internal sealed record OpusOffer(AudioStreamingOpusSource Source, AudioStreamingOpusFormat Format) : AudioStreamingBody;
    internal sealed record OpusConfiguration(ushort PreSkipFrames) : AudioStreamingBody;
    internal sealed record OpusData(long Sequence, byte[] Bytes) : AudioStreamingBody;
    internal sealed record OpusEnd(long SourceFrames, long PacketCount, long TotalEncodedBytes, byte[] Sha256) : AudioStreamingBody;
    internal sealed record OpusOutputReady() : AudioStreamingBody;
}
internal sealed record AudioStreamingMessage(Guid StreamId, AudioStreamingBody Body);

// Structural codec only. No account, connection, playback or file authorization is implied.
// Callers own mutable byte arrays until Encode returns; admitted stream state must freeze its descriptor.
internal static class AudioStreamingWire
{
    public const int MaximumMessageBytes = 12288;
    public const int MaximumPcmDataBytes = MaximumMessageBytes - 28 - 8;
    public const uint MaximumReceiveWindowBytes = 1048576;
    public const long MaximumFileBytes = 16L * 1024 * 1024 * 1024;
    public const string FileReceiveCapability = "audio_file_receive_v1";
    public const string CaptureReceiveCapability = "audio_capture_receive_v1";
    // Structural codec availability does not install or advertise a receiving consumer.
    public const string OpusReceiveCapability = "audio_opus_bluetooth_receive_v1";
    public const int MaximumOpusPacketBytes = 640;
    public const ushort MaximumOpusPreSkipFrames = 3840;
    public const long MaximumOpusPacketCount = long.MaxValue / 960;

    public static byte[] Encode(AudioStreamingMessage message)
    {
        Validate(message);
        (int opcode, int size) = message.Body switch
        {
            AudioStreamingBody.FileOffer => (1, 56), AudioStreamingBody.CaptureOffer => (2, 16),
            AudioStreamingBody.Accept => (3, 4), AudioStreamingBody.PcmData data => (4, 8 + data.Bytes.Length),
            AudioStreamingBody.Credit => (5, 8), AudioStreamingBody.End => (6, 40),
            AudioStreamingBody.ContentVerified => (7, 40), AudioStreamingBody.OutputReady => (8, 16),
            AudioStreamingBody.PlaybackComplete => (9, 12), AudioStreamingBody.Stop => (10, 4),
            AudioStreamingBody.OpusOffer => (11, 16), AudioStreamingBody.OpusConfiguration => (12, 4),
            AudioStreamingBody.OpusData data => (13, 8 + data.Bytes.Length), AudioStreamingBody.OpusEnd => (14, 56),
            AudioStreamingBody.OpusOutputReady => (15, 0),
            _ => throw new InvalidDataException("Unknown audio message.")
        };
        var bytes = new byte[28 + size]; var writer = new Writer(bytes);
        writer.U32(0x53424155); writer.U8(1); writer.U8(checked((byte)opcode)); writer.U16(0);
        writer.Id(message.StreamId); writer.U32((uint)size);
        switch (message.Body)
        {
            case AudioStreamingBody.FileOffer m: writer.Id(m.TransferId); writer.Counter(m.Length); writer.Bytes(m.Sha256); break;
            case AudioStreamingBody.CaptureOffer m: writer.Format(m.Format); break;
            case AudioStreamingBody.Accept m: writer.U32(m.ReceiveWindowBytes); break;
            case AudioStreamingBody.PcmData m: writer.Counter(m.ByteOffset); writer.Bytes(m.Bytes); break;
            case AudioStreamingBody.Credit m: writer.Counter(m.RetiredBytes); break;
            case AudioStreamingBody.End m: writer.Counter(m.TotalBytes); writer.Bytes(m.Sha256); break;
            case AudioStreamingBody.ContentVerified m: writer.Counter(m.TotalBytes); writer.Bytes(m.Sha256); break;
            case AudioStreamingBody.OutputReady m: writer.Format(m.Format); break;
            case AudioStreamingBody.PlaybackComplete m: writer.Counter(m.SourceFrames); writer.U32(m.TrailingPaddingFrames); break;
            case AudioStreamingBody.Stop m: writer.U16((ushort)m.Reason); writer.U16(0); break;
            case AudioStreamingBody.OpusOffer m:
                writer.U8(1); writer.U8((byte)m.Source); writer.U8(m.Format.Channels); writer.U8(0);
                writer.U32(m.Format.SampleRate); writer.U16(m.Format.PacketFrames); writer.U16(0); writer.U32(m.Format.Bitrate); break;
            case AudioStreamingBody.OpusConfiguration m: writer.U16(m.PreSkipFrames); writer.U16(0); break;
            case AudioStreamingBody.OpusData m: writer.Counter(m.Sequence); writer.Bytes(m.Bytes); break;
            case AudioStreamingBody.OpusEnd m:
                writer.Counter(m.SourceFrames); writer.Counter(m.PacketCount); writer.Counter(m.TotalEncodedBytes); writer.Bytes(m.Sha256); break;
            case AudioStreamingBody.OpusOutputReady: break;
        }
        return bytes;
    }

    public static AudioStreamingMessage Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 28 || bytes.Length > MaximumMessageBytes) throw new InvalidDataException("Invalid audio message size.");
        var reader = new Reader(bytes);
        if (reader.U32() != 0x53424155 || reader.U8() != 1) throw new InvalidDataException("Unsupported audio header.");
        var opcode = reader.U8();
        if (reader.U16() != 0) throw new InvalidDataException("Nonzero audio header reserved bits.");
        var id = reader.Id(); var length = reader.U32();
        if (length != reader.Remaining) throw new InvalidDataException("Audio body length mismatch.");
        AudioStreamingBody body;
        switch (opcode)
        {
            case 1: body = new AudioStreamingBody.FileOffer(reader.Id(), reader.Counter(), reader.Bytes(32)); break;
            case 2: body = new AudioStreamingBody.CaptureOffer(reader.Format()); break;
            case 3: body = new AudioStreamingBody.Accept(reader.U32()); break;
            case 4:
                var offset = reader.Counter(); body = new AudioStreamingBody.PcmData(offset, reader.Bytes(reader.Remaining)); break;
            case 5: body = new AudioStreamingBody.Credit(reader.Counter()); break;
            case 6: body = new AudioStreamingBody.End(reader.Counter(), reader.Bytes(32)); break;
            case 7: body = new AudioStreamingBody.ContentVerified(reader.Counter(), reader.Bytes(32)); break;
            case 8: body = new AudioStreamingBody.OutputReady(reader.Format()); break;
            case 9: body = new AudioStreamingBody.PlaybackComplete(reader.Counter(), reader.U32()); break;
            case 10:
                var reason = (AudioStreamingStopReason)reader.U16();
                if (reader.U16() != 0) throw new InvalidDataException("Nonzero stop reserved bits.");
                body = new AudioStreamingBody.Stop(reason); break;
            case 11:
                if (reader.U8() != 1) throw new InvalidDataException("Unsupported compressed audio codec.");
                var source = (AudioStreamingOpusSource)reader.U8(); var channels = reader.U8();
                if (!Enum.IsDefined(source) || reader.U8() != 0 || reader.U32() != 48000 || reader.U16() != 960 || reader.U16() != 0)
                    throw new InvalidDataException("Invalid Opus source or profile.");
                body = new AudioStreamingBody.OpusOffer(source, new(channels, reader.U32())); break;
            case 12:
                var skip = reader.U16();
                if (reader.U16() != 0) throw new InvalidDataException("Nonzero Opus configuration reserved bits.");
                body = new AudioStreamingBody.OpusConfiguration(skip); break;
            case 13:
                var sequence = reader.Counter();
                if (reader.Remaining is not (320 or 480 or 640)) throw new InvalidDataException("Invalid Opus packet size.");
                body = new AudioStreamingBody.OpusData(sequence, reader.Bytes(reader.Remaining)); break;
            case 14:
                body = new AudioStreamingBody.OpusEnd(reader.Counter(), reader.Counter(), reader.Counter(), reader.Bytes(32)); break;
            case 15: body = new AudioStreamingBody.OpusOutputReady(); break;
            default: throw new InvalidDataException("Unknown audio opcode.");
        }
        if (reader.Remaining != 0) throw new InvalidDataException("Trailing audio body bytes.");
        var message = new AudioStreamingMessage(id, body); Validate(message); return message;
    }

    private static void Validate(AudioStreamingMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.StreamId == Guid.Empty) throw new InvalidDataException("Empty stream ID.");
        switch (message.Body)
        {
            case AudioStreamingBody.FileOffer m:
                if (m.TransferId == Guid.Empty || m.Length <= 0 || m.Length > MaximumFileBytes)
                    throw new InvalidDataException("Invalid audio file binding.");
                Hash(m.Sha256); break;
            case AudioStreamingBody.CaptureOffer m: ArgumentNullException.ThrowIfNull(m.Format); break;
            case AudioStreamingBody.OutputReady m: ArgumentNullException.ThrowIfNull(m.Format); break;
            case AudioStreamingBody.Accept m:
                if (m.ReceiveWindowBytes > MaximumReceiveWindowBytes) throw new InvalidDataException("Audio window exceeds limit.");
                break;
            case AudioStreamingBody.PcmData m:
                if (m.Bytes is null || m.Bytes.Length == 0 || m.Bytes.Length > MaximumPcmDataBytes ||
                    m.ByteOffset < 0 || m.ByteOffset > long.MaxValue - m.Bytes.Length)
                    throw new InvalidDataException("Invalid audio data extent.");
                break;
            case AudioStreamingBody.Credit m: Counter(m.RetiredBytes); break;
            case AudioStreamingBody.End m: Counter(m.TotalBytes); Hash(m.Sha256); break;
            case AudioStreamingBody.ContentVerified m: Counter(m.TotalBytes); Hash(m.Sha256); break;
            case AudioStreamingBody.PlaybackComplete m:
                if (m.SourceFrames < 0 || m.SourceFrames > long.MaxValue - m.TrailingPaddingFrames)
                    throw new InvalidDataException("Invalid audio completion extent.");
                break;
            case AudioStreamingBody.Stop m:
                if (!Enum.IsDefined(m.Reason)) throw new InvalidDataException("Unknown audio stop reason.");
                break;
            case AudioStreamingBody.OpusOffer m:
                ArgumentNullException.ThrowIfNull(m.Format);
                if (!Enum.IsDefined(m.Source)) throw new InvalidDataException("Unknown Opus source kind.");
                break;
            case AudioStreamingBody.OpusConfiguration m:
                if (m.PreSkipFrames > MaximumOpusPreSkipFrames) throw new InvalidDataException("Invalid Opus pre-skip.");
                break;
            case AudioStreamingBody.OpusData m:
                if (m.Sequence < 0 || m.Sequence >= MaximumOpusPacketCount || m.Bytes is null || m.Bytes.Length is not (320 or 480 or 640))
                    throw new InvalidDataException("Invalid Opus packet extent.");
                break;
            case AudioStreamingBody.OpusEnd m:
                if (m.SourceFrames <= 0 || m.SourceFrames > long.MaxValue - MaximumOpusPreSkipFrames ||
                    m.PacketCount <= 0 || m.PacketCount > MaximumOpusPacketCount || m.TotalEncodedBytes <= 0 ||
                    m.TotalEncodedBytes % m.PacketCount != 0 || m.TotalEncodedBytes / m.PacketCount is not (320 or 480 or 640))
                    throw new InvalidDataException("Invalid Opus end counters.");
                Hash(m.Sha256); break;
            case AudioStreamingBody.OpusOutputReady: break;
            default: throw new InvalidDataException("Unknown audio message body.");
        }
    }
    private static void Counter(long value) { if (value < 0) throw new InvalidDataException("Audio counter is outside signed 64-bit range."); }
    private static void Hash(byte[] value) { if (value is null || value.Length != 32) throw new InvalidDataException("Audio SHA-256 must be exactly 32 bytes."); }

    private ref struct Writer(Span<byte> bytes)
    {
        private Span<byte> _remaining = bytes;
        private Span<byte> Take(int count) { var result = _remaining[..count]; _remaining = _remaining[count..]; return result; }
        public void U8(byte value) => Take(1)[0] = value;
        public void U16(ushort value) => BinaryPrimitives.WriteUInt16BigEndian(Take(2), value);
        public void U32(uint value) => BinaryPrimitives.WriteUInt32BigEndian(Take(4), value);
        public void Counter(long value) => BinaryPrimitives.WriteUInt64BigEndian(Take(8), (ulong)value);
        public void Bytes(ReadOnlySpan<byte> value) => value.CopyTo(Take(value.Length));
        public void Id(Guid value)
        {
            if (!value.TryWriteBytes(Take(16), bigEndian: true, out var written) || written != 16)
                throw new InvalidDataException("Unable to encode network-order UUID.");
        }
        public void Format(AudioStreamingPcmFormat value)
        {
            U32(value.SampleRate); U16(value.Channels); U8((byte)value.Encoding); U8(value.ValidBits);
            U8(value.WaveChannelMask.HasValue ? (byte)1 : (byte)0); U8(0); U16(0); U32(value.WaveChannelMask ?? 0);
        }
    }
    private ref struct Reader(ReadOnlySpan<byte> bytes)
    {
        private ReadOnlySpan<byte> _remaining = bytes;
        public int Remaining => _remaining.Length;
        private ReadOnlySpan<byte> Take(int count)
        {
            if (count < 0 || count > _remaining.Length) throw new InvalidDataException("Truncated audio message.");
            var result = _remaining[..count]; _remaining = _remaining[count..]; return result;
        }
        public byte U8() => Take(1)[0];
        public ushort U16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));
        public uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));
        public long Counter()
        {
            var value = BinaryPrimitives.ReadUInt64BigEndian(Take(8));
            if (value > long.MaxValue) throw new InvalidDataException("Audio counter is outside signed 64-bit range.");
            return (long)value;
        }
        public byte[] Bytes(int count) => Take(count).ToArray();
        public Guid Id() => new(Take(16), bigEndian: true);
        public AudioStreamingPcmFormat Format()
        {
            var rate = U32(); var channels = U16(); var encoding = (AudioStreamingEncoding)U8(); var bits = U8();
            var present = U8();
            if (present > 1 || U8() != 0 || U16() != 0) throw new InvalidDataException("Invalid PCM layout flags.");
            var mask = U32();
            if (present == 0 && mask != 0) throw new InvalidDataException("Unknown layout must have zero mask field.");
            return new(rate, channels, encoding, bits, present == 1 ? mask : null);
        }
    }
}
