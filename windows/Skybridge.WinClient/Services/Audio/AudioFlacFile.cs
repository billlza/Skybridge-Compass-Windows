using System.Buffers.Binary;
using System.Text;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioFlacMetadataError { Truncated, Malformed, UnsupportedContainer, MetadataLimit, InvalidReadLength, Oversized }

internal sealed class AudioFlacMetadataException(AudioFlacMetadataError reason, Exception? inner = null)
    : IOException($"FLAC metadata inspection failed: {reason}.", inner)
{
    public AudioFlacMetadataError Reason { get; } = reason;
}

// Declarations only. A decoder and output endpoint must independently validate actual frames and support.
internal sealed record AudioFlacMetadata(AudioStreamingPcmFormat DecodedFormat, long? TotalFrames,
    string? PcmMd5Hex, long FirstFrameByteOffset, ushort MinimumBlockFrames, ushort MaximumBlockFrames,
    uint? MinimumFrameBytes, uint? MaximumFrameBytes, bool HasExplicitChannelMask);

internal static class AudioFlacFile
{
    public static readonly long MaximumFileBytes = AudioStreamingWire.MaximumFileBytes;
    public const long MaximumMetadataBytes = 64 * 1024 * 1024;
    public const int MaximumBlocks = 4096;
    public const int MaximumCommentBytes = 1048576;
    public const int MaximumCommentFields = 4096;
    public const int MaximumReadBytes = 65536;
    private const string MaskField = "WAVEFORMATEXTENSIBLE_CHANNEL_MASK";
    private static readonly uint[] DefaultMasks = [4, 3, 7, 0x33, 0x37, 0x3f, 0x70f, 0x63f];
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Reads RFC 9639 native FLAC declarations from one caller-owned immutable/verified source.
    /// Owns no file and does not decode, validate frame checksums, load artwork or infer output support.
    /// Cancellation waits for the actual source read; exceptions are not replaced by metadata defaults.
    /// FLAC declares signed integer precision, not a PCM container. DecodedFormat specifies reversible
    /// little-endian, interleaved, high-aligned valid bits in the smallest 8/16/24/32-bit container,
    /// using offset binary for 8-bit. Explicit speaker masks, including zero/partial masks, stay explicit.
    /// </summary>
    public static async Task<AudioFlacMetadata> InspectAsync(long fileSize,
        Func<long, int, CancellationToken, Task<byte[]>> read, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(read);
        cancellationToken.ThrowIfCancellationRequested();
        if (fileSize < 0 || fileSize > MaximumFileBytes) throw Failure(AudioFlacMetadataError.Oversized);
        var signature = await ReadBytesAsync(0, 4, fileSize, read, cancellationToken).ConfigureAwait(false);
        if (!signature.AsSpan().SequenceEqual("fLaC"u8)) throw Failure(AudioFlacMetadataError.UnsupportedContainer);
        long offset = 4;
        byte[]? streamInfo = null;
        uint? explicitMask = null;
        bool commentsSeen = false;
        int blocks = 0;
        while (true)
        {
            if (++blocks > MaximumBlocks || offset > MaximumMetadataBytes - 4) throw Failure(AudioFlacMetadataError.MetadataLimit);
            var header = await ReadBytesAsync(offset, 4, fileSize, read, cancellationToken).ConfigureAwait(false);
            int type = header[0] & 0x7f;
            bool last = (header[0] & 0x80) != 0;
            int length = (int)BigEndian(header, 1, 3);
            long start = offset + 4;
            if (length > fileSize - start) throw Failure(AudioFlacMetadataError.Truncated);
            if (length > MaximumMetadataBytes - start) throw Failure(AudioFlacMetadataError.MetadataLimit);
            if (type == 127 || (blocks == 1 && type != 0)) throw Failure(AudioFlacMetadataError.Malformed);
            switch (type)
            {
                case 0:
                    if (streamInfo is not null || length != 34) throw Failure(AudioFlacMetadataError.Malformed);
                    streamInfo = await ReadBytesAsync(start, length, fileSize, read, cancellationToken).ConfigureAwait(false);
                    break;
                case 4:
                    if (commentsSeen) throw Failure(AudioFlacMetadataError.Malformed);
                    commentsSeen = true;
                    if (length > MaximumCommentBytes) throw Failure(AudioFlacMetadataError.MetadataLimit);
                    var comment = new byte[length];
                    int copied = 0;
                    while (copied < length)
                    {
                        var part = await ReadBytesAsync(start + copied, Math.Min(length - copied, MaximumReadBytes),
                            fileSize, read, cancellationToken).ConfigureAwait(false);
                        part.CopyTo(comment, copied);
                        copied += part.Length;
                    }
                    explicitMask = ChannelMask(comment, cancellationToken);
                    break;
                // Other payloads are skipped without interpreting application metadata or fetching pictures.
            }
            offset = start + length;
            if (last) break;
        }
        if (offset == fileSize) throw Failure(AudioFlacMetadataError.Truncated);
        if (streamInfo is not { Length: 34 } info) throw Failure(AudioFlacMetadataError.Malformed);
        ushort minimumBlock = (ushort)BigEndian(info, 0, 2);
        ushort maximumBlock = (ushort)BigEndian(info, 2, 2);
        uint minimumFrame = (uint)BigEndian(info, 4, 3);
        uint maximumFrame = (uint)BigEndian(info, 7, 3);
        uint rate = (uint)(BigEndian(info, 10, 3) >> 4);
        ushort channels = (ushort)(((info[12] >> 1) & 7) + 1);
        byte bits = (byte)((((info[12] & 1) << 4) | (info[13] >> 4)) + 1);
        long frames = ((long)(info[13] & 15) << 32) | (long)BigEndian(info, 14, 4);
        if (minimumBlock < 16 || maximumBlock < minimumBlock || rate == 0 || bits is < 4 or > 32 ||
            (minimumFrame != 0 && maximumFrame != 0 && minimumFrame > maximumFrame)) throw Failure(AudioFlacMetadataError.Malformed);
        var encoding = bits switch
        {
            <= 8 => AudioStreamingEncoding.Unsigned8,
            <= 16 => AudioStreamingEncoding.Signed16,
            <= 24 => AudioStreamingEncoding.Signed24,
            _ => AudioStreamingEncoding.Signed32
        };
        var format = new AudioStreamingPcmFormat(rate, channels, encoding, bits, explicitMask ?? DefaultMasks[channels - 1]);
        string? digest = info.AsSpan(18, 16).IndexOfAnyExcept((byte)0) < 0 ? null : Convert.ToHexStringLower(info.AsSpan(18, 16));
        cancellationToken.ThrowIfCancellationRequested();
        return new(format, frames == 0 ? null : frames, digest, offset, minimumBlock, maximumBlock,
            minimumFrame == 0 ? null : minimumFrame, maximumFrame == 0 ? null : maximumFrame, explicitMask.HasValue);
    }

    private static uint? ChannelMask(byte[] bytes, CancellationToken cancellationToken)
    {
        int cursor = 0;
        int Length()
        {
            if (bytes.Length - cursor < 4) throw Failure(AudioFlacMetadataError.Malformed);
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(cursor, 4));
            cursor += 4;
            if (value > int.MaxValue) throw Failure(AudioFlacMetadataError.Malformed);
            return (int)value;
        }
        string Text(int count)
        {
            if (count > bytes.Length - cursor) throw Failure(AudioFlacMetadataError.Malformed);
            string value;
            try { value = StrictUtf8.GetString(bytes, cursor, count); }
            catch (DecoderFallbackException failure) { throw new AudioFlacMetadataException(AudioFlacMetadataError.Malformed, failure); }
            cursor += count;
            return value;
        }
        _ = Text(Length());
        int fields = Length();
        if (fields > MaximumCommentFields) throw Failure(AudioFlacMetadataError.MetadataLimit);
        uint? mask = null;
        for (int i = 0; i < fields; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string field = Text(Length());
            int separator = field.IndexOf('=');
            if (separator <= 0) throw Failure(AudioFlacMetadataError.Malformed);
            foreach (char character in field.AsSpan(0, separator))
                if (character is < ' ' or > '~') throw Failure(AudioFlacMetadataError.Malformed);
            if (field.AsSpan(0, separator).Equals(MaskField, StringComparison.OrdinalIgnoreCase))
            {
                if (mask.HasValue) throw Failure(AudioFlacMetadataError.Malformed);
                var value = field.AsSpan(separator + 1);
                if (value.Length < 3 || !value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) throw Failure(AudioFlacMetadataError.Malformed);
                uint parsed = 0;
                foreach (char character in value[2..])
                {
                    uint digit = character switch
                    {
                        >= '0' and <= '9' => (uint)(character - '0'),
                        >= 'a' and <= 'f' => (uint)(character - 'a' + 10),
                        >= 'A' and <= 'F' => (uint)(character - 'A' + 10),
                        _ => throw Failure(AudioFlacMetadataError.Malformed)
                    };
                    if (parsed > (uint.MaxValue - digit) / 16) throw Failure(AudioFlacMetadataError.Malformed);
                    parsed = parsed * 16 + digit;
                }
                mask = parsed;
            }
        }
        if (cursor != bytes.Length) throw Failure(AudioFlacMetadataError.Malformed);
        return mask;
    }

    private static async Task<byte[]> ReadBytesAsync(long offset, int count, long fileSize,
        Func<long, int, CancellationToken, Task<byte[]>> read, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (count is < 1 or > MaximumReadBytes || offset < 0 || offset > fileSize || count > fileSize - offset)
            throw Failure(AudioFlacMetadataError.Truncated);
        var bytes = await read(offset, count, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (bytes is null) throw Failure(AudioFlacMetadataError.InvalidReadLength);
        if (bytes.Length < count) throw Failure(AudioFlacMetadataError.Truncated);
        if (bytes.Length != count) throw Failure(AudioFlacMetadataError.InvalidReadLength);
        return bytes;
    }

    private static ulong BigEndian(byte[] bytes, int offset, int count)
    {
        ulong value = 0;
        for (int i = 0; i < count; i++) value = value << 8 | bytes[offset + i];
        return value;
    }
    private static AudioFlacMetadataException Failure(AudioFlacMetadataError reason) => new(reason);
}
