using System.Buffers.Binary;

namespace Skybridge.WinClient.Services.Audio;

// Describes bytes at the renderer boundary, not the original music's precision.
internal sealed record ExactPcmFormat
{
    public uint SampleRate { get; }
    public ushort Channels { get; }
    public ushort ContainerBits { get; }
    public ushort ValidBits { get; }
    public bool FloatingPoint { get; }
    public uint ChannelMask { get; }
    public ushort BytesPerFrame { get; }
    public uint BytesPerSecond { get; }

    public ExactPcmFormat(uint sampleRate, ushort channels, ushort containerBits,
        ushort validBits, bool floatingPoint, uint channelMask)
    {
        if (sampleRate == 0 || channels == 0 || containerBits is not (8 or 16 or 24 or 32 or 64) ||
            validBits == 0 || validBits > containerBits ||
            (floatingPoint && (containerBits is not (32 or 64) || validBits != containerBits)))
        {
            throw new ArgumentException("PCM rate, channels, container and declared precision must be explicit and valid.");
        }

        SampleRate = sampleRate;
        Channels = channels;
        ContainerBits = containerBits;
        ValidBits = validBits;
        FloatingPoint = floatingPoint;
        ChannelMask = channelMask; // Zero is explicit DIRECTOUT; never infer it from missing layout metadata.
        BytesPerFrame = checked((ushort)(channels * (containerBits / 8)));
        BytesPerSecond = checked(sampleRate * BytesPerFrame);
    }

    // WAVEFORMATEXTENSIBLE uses little-endian PCM; valid integer bits are left-aligned.
    // 8-bit integer PCM is unsigned. The renderer does not repack, scale, or convert samples.
    public byte[] ToWaveFormatExtensible()
    {
        var bytes = new byte[40];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2), Channels);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), SampleRate);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), BytesPerSecond);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(12), BytesPerFrame);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(14), ContainerBits);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(16), 22);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(18), ValidBits);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20), ChannelMask);
        new Guid(FloatingPoint ? "00000003-0000-0010-8000-00aa00389b71" :
            "00000001-0000-0010-8000-00aa00389b71").TryWriteBytes(bytes.AsSpan(24));
        return bytes;
    }
}
