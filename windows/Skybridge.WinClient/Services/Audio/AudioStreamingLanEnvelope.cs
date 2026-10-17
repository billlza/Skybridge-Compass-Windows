namespace Skybridge.WinClient.Services.Audio;

/// <summary>SBE1 kind 2 inside the existing authenticated MAIN encryption and padding.</summary>
internal static class AudioStreamingLanEnvelope
{
    internal const int HeaderBytes = 13;
    internal const int MaximumBytes = HeaderBytes + AudioStreamingWire.MaximumMessageBytes;
    private static ReadOnlySpan<byte> Prefix => [0x53, 0x42, 0x45, 0x31, 2];

    internal static byte[] Encode(AudioStreamingMessage message)
    {
        var payload = AudioStreamingWire.Encode(message);
        var bytes = new byte[HeaderBytes + payload.Length];
        Prefix.CopyTo(bytes);
        payload.CopyTo(bytes.AsSpan(HeaderBytes));
        return bytes;
    }

    // Null means a different carrier. A recognized malformed audio envelope always throws.
    internal static AudioStreamingMessage? DecodeIfPresent(ReadOnlySpan<byte> bytes)
    {
        if (!bytes.StartsWith(Prefix)) return null;
        if (bytes.Length < HeaderBytes || bytes.Length > MaximumBytes)
            throw new InvalidDataException("Invalid LAN audio envelope size.");
        if (bytes.Slice(Prefix.Length, HeaderBytes - Prefix.Length).ContainsAnyExcept((byte)0))
            throw new InvalidDataException("LAN audio envelope reserved timestamp must be zero.");
        return AudioStreamingWire.Decode(bytes[HeaderBytes..]);
    }
}
