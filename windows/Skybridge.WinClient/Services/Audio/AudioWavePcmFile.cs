using System.Buffers.Binary;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioWavePcmFileError
{
    Oversized, Truncated, Malformed, UnsupportedContainer, UnsupportedEncoding,
    UnsupportedLayout, UndeclaredPrecision, ChunkLimit, InvalidReadLength
}

internal sealed class AudioWavePcmFileException : IOException
{
    public AudioWavePcmFileError Reason { get; }

    internal AudioWavePcmFileException(AudioWavePcmFileError reason, Exception? innerException = null)
        : base($"WAVE inspection failed: {reason}.", innerException) => Reason = reason;
}

// Container declarations only: neither a content hash nor proof of output admission or signal precision.
internal sealed record AudioWavePcmMetadata
{
    public AudioStreamingPcmFormat Format { get; }
    public long PcmByteOffset { get; }
    public long PcmByteCount { get; }
    public long FrameCount => PcmByteCount / Format.BytesPerFrame;

    internal AudioWavePcmMetadata(AudioStreamingPcmFormat format, long pcmByteOffset, long pcmByteCount)
    {
        Format = format;
        PcmByteOffset = pcmByteOffset;
        PcmByteCount = pcmByteCount;
    }
}

internal static class AudioWavePcmFile
{
    public const int MaximumChunks = 4096;
    public const int MaximumReadBytes = 40;
    // RIFF's DWORD length excludes its first eight bytes. RF64 is not accepted.
    public static readonly long MaximumFileBytes = Math.Min(AudioStreamingWire.MaximumFileBytes, (long)uint.MaxValue + 8);

    /// <summary>
    /// Inspects one caller-owned immutable or verified source. The size and every exact-range read
    /// must refer to that same source. This parser owns no descriptor and never closes, hashes,
    /// decodes or converts sample bytes. Unknown payloads and padding are skipped by checked offsets.
    /// Every chunk is inspected, including chunks after data; every read is at most 40 bytes.
    /// Cancellation waits for the actual read to return. The caller retains responsibility for a
    /// source that does not cooperate with cancellation. Callback failures propagate unchanged.
    /// </summary>
    public static async Task<AudioWavePcmMetadata> InspectAsync(long fileSize,
        Func<long, int, CancellationToken, Task<byte[]>> read, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(read);
        cancellationToken.ThrowIfCancellationRequested();
        if (fileSize < 0) throw Failure(AudioWavePcmFileError.Malformed);
        if (fileSize > MaximumFileBytes) throw Failure(AudioWavePcmFileError.Oversized);
        if (fileSize < 12) throw Failure(AudioWavePcmFileError.Truncated);

        var header = await ReadBytesAsync(0, 12, fileSize, read, cancellationToken).ConfigureAwait(false);
        if (U32(header, 0) != 0x46464952 || U32(header, 8) != 0x45564157) // RIFF / WAVE
            throw Failure(AudioWavePcmFileError.UnsupportedContainer);
        long riffEnd = (long)U32(header, 4) + 8;
        if (riffEnd < 12) throw Failure(AudioWavePcmFileError.Malformed);
        if (riffEnd > fileSize) throw Failure(AudioWavePcmFileError.Truncated);
        if (riffEnd != fileSize) throw Failure(AudioWavePcmFileError.UnsupportedLayout);

        long offset = 12;
        int chunks = 0;
        AudioStreamingPcmFormat? format = null;
        (long Offset, long Count)? pcm = null;
        while (offset < riffEnd)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (chunks >= MaximumChunks) throw Failure(AudioWavePcmFileError.ChunkLimit);
            chunks++;
            if (riffEnd - offset < 8) throw Failure(AudioWavePcmFileError.Truncated);
            var chunk = await ReadBytesAsync(offset, 8, fileSize, read, cancellationToken).ConfigureAwait(false);
            long length = U32(chunk, 4);
            long start = offset + 8; // Bounded by riffEnd, which is at most uint.MaxValue + 8.
            long padding = length & 1;
            if (length > riffEnd - start || padding > riffEnd - start - length)
                throw Failure(AudioWavePcmFileError.Truncated);
            switch (U32(chunk, 0))
            {
                case 0x20746d66: // fmt
                    if (format is not null) throw Failure(AudioWavePcmFileError.UnsupportedLayout);
                    if (length < 16) throw Failure(AudioWavePcmFileError.Truncated);
                    var bytes = await ReadBytesAsync(start, (int)Math.Min(length, MaximumReadBytes),
                        fileSize, read, cancellationToken).ConfigureAwait(false);
                    format = ParseFormat(bytes, length);
                    break;
                case 0x61746164: // data
                    if (pcm is not null) throw Failure(AudioWavePcmFileError.UnsupportedLayout);
                    pcm = (start, length);
                    break;
                case 0x5453494c: // LIST
                    if (length < 4) throw Failure(AudioWavePcmFileError.Malformed);
                    var type = await ReadBytesAsync(start, 4, fileSize, read, cancellationToken).ConfigureAwait(false);
                    if (U32(type, 0) == 0x6c766177) // wavl
                        throw Failure(AudioWavePcmFileError.UnsupportedLayout);
                    break;
                case 0x746e6c73: // slnt
                    throw Failure(AudioWavePcmFileError.UnsupportedLayout);
            }
            offset = start + length + padding;
        }
        if (format is null || pcm is null) throw Failure(AudioWavePcmFileError.Malformed);
        if (pcm.Value.Count % format.BytesPerFrame != 0) throw Failure(AudioWavePcmFileError.Malformed);
        cancellationToken.ThrowIfCancellationRequested();
        return new AudioWavePcmMetadata(format, pcm.Value.Offset, pcm.Value.Count);
    }

    private static AudioStreamingPcmFormat ParseFormat(byte[] bytes, long chunkSize)
    {
        ushort tag = U16(bytes, 0);
        ushort channels = U16(bytes, 2);
        uint rate = U32(bytes, 4);
        uint byteRate = U32(bytes, 8);
        ushort blockAlign = U16(bytes, 12);
        ushort containerBits = U16(bytes, 14);
        ushort validBits = containerBits;
        uint? mask = null;
        uint encodingTag;
        switch (tag)
        {
            case 1:
            case 3:
                // Legacy PCM/float ignores extension bytes, including an absent or invalid cbSize.
                encodingTag = tag;
                break;
            case 0xfffe:
                if (chunkSize < 40) throw Failure(AudioWavePcmFileError.Truncated);
                ushort extra = U16(bytes, 16);
                if (extra < 22 || (long)extra + 18 > chunkSize) throw Failure(AudioWavePcmFileError.Malformed);
                validBits = U16(bytes, 18);
                if (validBits == 0) throw Failure(AudioWavePcmFileError.UndeclaredPrecision);
                mask = U32(bytes, 20);
                ReadOnlySpan<byte> guidTail = [0, 0, 0x10, 0, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71];
                if (!bytes.AsSpan(28, 12).SequenceEqual(guidTail))
                    throw Failure(AudioWavePcmFileError.UnsupportedEncoding);
                encodingTag = U32(bytes, 24);
                break;
            default:
                throw Failure(AudioWavePcmFileError.UnsupportedEncoding);
        }
        AudioStreamingEncoding encoding = (encodingTag, containerBits) switch
        {
            (1, 8) => AudioStreamingEncoding.Unsigned8,
            (1, 16) => AudioStreamingEncoding.Signed16,
            (1, 24) => AudioStreamingEncoding.Signed24,
            (1, 32) => AudioStreamingEncoding.Signed32,
            (1, 64) => AudioStreamingEncoding.Signed64,
            (3, 32) => AudioStreamingEncoding.Float32,
            (3, 64) => AudioStreamingEncoding.Float64,
            _ => throw Failure(AudioWavePcmFileError.UnsupportedEncoding)
        };
        if (validBits == 0 || validBits > containerBits) throw Failure(AudioWavePcmFileError.Malformed);
        AudioStreamingPcmFormat format;
        try
        {
            // Preserve null legacy layout and every explicit mask, including DIRECTOUT zero and
            // mappings an output may reject. ExactPcmFormat/output admission is a separate boundary.
            format = new AudioStreamingPcmFormat(rate, channels, encoding, checked((byte)validBits), mask);
        }
        catch (InvalidDataException error)
        {
            throw new AudioWavePcmFileException(AudioWavePcmFileError.Malformed, error);
        }
        if (blockAlign != format.BytesPerFrame || (ulong)byteRate != (ulong)rate * format.BytesPerFrame)
            throw Failure(AudioWavePcmFileError.Malformed);
        return format;
    }

    private static async Task<byte[]> ReadBytesAsync(long offset, int count, long fileSize,
        Func<long, int, CancellationToken, Task<byte[]>> read, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (offset < 0 || offset > fileSize || count <= 0 || count > MaximumReadBytes || count > fileSize - offset)
            throw Failure(AudioWavePcmFileError.Truncated);
        var bytes = await read(offset, count, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (bytes is null) throw Failure(AudioWavePcmFileError.InvalidReadLength);
        if (bytes.Length < count) throw Failure(AudioWavePcmFileError.Truncated);
        if (bytes.Length != count) throw Failure(AudioWavePcmFileError.InvalidReadLength);
        return bytes.ToArray(); // Bounded copy; no caller-owned array is retained in metadata.
    }

    private static ushort U16(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset));
    private static uint U32(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset));
    private static AudioWavePcmFileException Failure(AudioWavePcmFileError reason) => new(reason);
}
