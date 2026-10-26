using System.Buffers.Binary;
using System.Runtime.ExceptionServices;
using System.Text;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioAlacFileError
{
    Truncated, Malformed, UnsupportedContainer, UnsupportedLayout, UnsupportedEncoding,
    MetadataLimit, InvalidReadLength, Oversized
}

internal sealed class AudioAlacFileException(AudioAlacFileError reason)
    : IOException($"ALAC container inspection failed: {reason}.")
{
    internal AudioAlacFileError Reason { get; } = reason;
}

// Container declarations and verified ranges only. This is not a decoded-file witness,
// an account authorization or a claim that an output device supports the format.
internal sealed class AudioAlacMetadata(AudioStreamingPcmFormat format, long encodedBytes,
    byte[] configuration, AudioAlacIndex index)
{
    private readonly byte[] _configuration = configuration.ToArray();
    internal AudioStreamingPcmFormat DecodedFormat { get; } = format;
    internal long TotalFrames => index.Frames;
    internal long PacketCount => index.Packets;
    internal long EncodedAudioBytes { get; } = encodedBytes;
    internal uint MaximumFramesPerPacket => index.MaximumFrames;
    internal uint? MaximumPacketBytes => index.MaximumBytes;
    internal ReadOnlyMemory<byte> Configuration => _configuration;
    internal AudioAlacPacketCursor MakePacketCursor() => new(index);
}

internal sealed record AudioAlacPacket(long Index, long FirstFrameIndex, uint FrameCount,
    long ByteOffset, int ByteCount);

// Sequential paged traversal. The caller must keep the same immutable/commitment-verified
// source, and check its live ownership even on cached table reads. No callback is retained.
internal sealed class AudioAlacPacketCursor
{
    private readonly AudioAlacIndex _index;
    private readonly AudioAlacPage _timing, _offsets, _runs;
    private readonly AudioAlacPage? _sizes;
    private long _packet, _frames, _timingRows, _timingRemaining, _chunks, _chunkRemaining, _nextByte, _runIndex;
    private uint _packetFrames;
    private AudioAlacRun? _currentRun, _nextRun;
    private ExceptionDispatchInfo? _failure;
    private int _reading;

    internal AudioAlacPacketCursor(AudioAlacIndex index)
    {
        _index = index; _timing = new(index.Timing); _offsets = new(index.Offsets); _runs = new(index.Runs);
        _sizes = index.Sizes is { } sizes ? new(sizes) : null;
    }

    internal async Task<AudioAlacPacket?> NextAsync(
        Func<long, int, CancellationToken, Task<byte[]>> read, Action requireCurrent, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(read); ArgumentNullException.ThrowIfNull(requireCurrent);
        if (Interlocked.CompareExchange(ref _reading, 1, 0) != 0)
            throw new InvalidOperationException("An ALAC packet cursor permits one active read.");
        void Check() { token.ThrowIfCancellationRequested(); requireCurrent(); token.ThrowIfCancellationRequested(); }
        try
        {
            _failure?.Throw(); Check();
            if (_packet == _index.Packets)
            {
                Require(_frames == _index.Frames && _timingRemaining == 0 && _timingRows == _index.Timing.Count &&
                    _chunkRemaining == 0 && _chunks == _index.Offsets.Count &&
                    _runIndex + 1 == _index.Runs.Count && _nextRun is null);
                Check(); return null;
            }
            if (_timingRemaining == 0)
            {
                Require(_timingRows < _index.Timing.Count);
                uint count = await _timing.U32Async(_timingRows, 0, read, Check, token).ConfigureAwait(false);
                uint delta = await _timing.U32Async(_timingRows, 4, read, Check, token).ConfigureAwait(false);
                Require(count > 0 && count <= _index.Packets - _packet && delta > 0 && delta <= _index.MaximumFrames);
                _timingRows++; _timingRemaining = count; _packetFrames = delta;
            }
            if (_chunkRemaining == 0)
            {
                Require(_chunks < _index.Offsets.Count);
                long chunk = _chunks + 1;
                if (_currentRun is null)
                {
                    _currentRun = await LoadRunAsync(0, 0, read, Check, token).ConfigureAwait(false);
                    Require(_currentRun.FirstChunk == 1);
                    if (_index.Runs.Count > 1)
                        _nextRun = await LoadRunAsync(1, _currentRun.FirstChunk, read, Check, token).ConfigureAwait(false);
                }
                if (_nextRun is { } next && next.FirstChunk == chunk)
                {
                    _runIndex++; _currentRun = next;
                    _nextRun = _runIndex + 1 < _index.Runs.Count
                        ? await LoadRunAsync(_runIndex + 1, next.FirstChunk, read, Check, token).ConfigureAwait(false) : null;
                }
                var run = _currentRun;
                Require(run.FirstChunk <= chunk && (_nextRun is null || _nextRun.FirstChunk > chunk) &&
                    run.PacketsPerChunk <= _index.Packets - _packet);
                _nextByte = _index.Offsets.Stride == 8
                    ? await _offsets.U64Async(_chunks, read, Check, token).ConfigureAwait(false)
                    : await _offsets.U32Async(_chunks, 0, read, Check, token).ConfigureAwait(false);
                _chunkRemaining = run.PacketsPerChunk; _chunks++;
            }
            uint size;
            if (_index.FixedBytes is { } fixedBytes) size = fixedBytes;
            else
            {
                if (_sizes is null) throw new AudioAlacFileException(AudioAlacFileError.Malformed);
                size = await _sizes.U32Async(_packet, 0, read, Check, token).ConfigureAwait(false);
            }
            Require(size > 0 && size <= AudioAlacFile.MaximumPacketBytes &&
                (_index.MaximumBytes is null || size <= _index.MaximumBytes) &&
                _packetFrames <= _index.Frames - _frames && _index.ContainsMedia(_nextByte, size));
            var result = new AudioAlacPacket(_packet, _frames, _packetFrames, _nextByte, checked((int)size));
            Check();
            _packet++; _frames += _packetFrames; _timingRemaining--; _chunkRemaining--; _nextByte += size;
            return result;
        }
        catch (Exception failure) { _failure ??= ExceptionDispatchInfo.Capture(failure); throw; }
        finally { Volatile.Write(ref _reading, 0); }
    }

    private async Task<AudioAlacRun> LoadRunAsync(long row, long previous,
        Func<long, int, CancellationToken, Task<byte[]>> read, Action check, CancellationToken token)
    {
        uint first = await _runs.U32Async(row, 0, read, check, token).ConfigureAwait(false);
        uint count = await _runs.U32Async(row, 4, read, check, token).ConfigureAwait(false);
        uint description = await _runs.U32Async(row, 8, read, check, token).ConfigureAwait(false);
        Require(first > previous && first <= _index.Offsets.Count && count > 0 && count <= _index.Packets && description == 1);
        return new(first, count);
    }
    private static void Require(bool condition) => AudioAlacFile.Require(condition, AudioAlacFileError.Malformed);
}

// Matches the finite, self-contained mono/stereo ALAC profile used by Apple and Android.
// All table rows are checked, using bounded pages rather than a song-sized packet array.
internal static class AudioAlacFile
{
    internal const long MaximumFileBytes = 2L * 1024 * 1024 * 1024;
    internal const long MaximumMetadataBytes = 64L * 1024 * 1024;
    internal const int MaximumReadBytes = 65_536, MaximumBoxes = 4_096;
    internal const long MaximumPackets = 4_194_304;
    internal const uint MaximumPacketBytes = 2_097_120;

    internal static async Task<AudioAlacMetadata> InspectAsync(long fileSize,
        Func<long, int, CancellationToken, Task<byte[]>> read, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(read); token.ThrowIfCancellationRequested();
        Require(fileSize >= 0 && fileSize <= MaximumFileBytes, AudioAlacFileError.Oversized);
        var source = new AudioAlacSource(fileSize, read);
        var top = await source.BoxesAsync(0, fileSize, token).ConfigureAwait(false);
        Require(!top.Any(b => b.Type == "moof"), AudioAlacFileError.UnsupportedLayout);
        var ftyp = Single(top, "ftyp", AudioAlacFileError.UnsupportedContainer);
        Require(ftyp.Length >= 8 && ftyp.Length % 4 == 0);
        var moov = Single(top, "moov"); Require(moov.Length <= MaximumMetadataBytes, AudioAlacFileError.MetadataLimit);
        var movie = await source.ChildrenAsync(moov, token).ConfigureAwait(false);
        Require(!movie.Any(b => b.Type == "mvex"), AudioAlacFileError.UnsupportedLayout);
        var track = await source.ChildrenAsync(Single(movie, "trak", AudioAlacFileError.UnsupportedLayout), token).ConfigureAwait(false);
        Require(!track.Any(b => b.Type == "edts"), AudioAlacFileError.UnsupportedLayout);
        uint flags = U32(await source.PrefixAsync(Single(track, "tkhd"), 4, token).ConfigureAwait(false), 0);
        Require(flags >> 24 <= 1 && (flags & 1) != 0, AudioAlacFileError.UnsupportedLayout);
        var media = await source.ChildrenAsync(Single(track, "mdia"), token).ConfigureAwait(false);
        var handler = await source.PrefixAsync(Single(media, "hdlr"), 12, token).ConfigureAwait(false);
        Require(U32(handler, 0) == 0 && FourCC(handler, 8) == "soun", AudioAlacFileError.UnsupportedLayout);
        var mdhd = Single(media, "mdhd");
        uint version = U32(await source.PrefixAsync(mdhd, 4, token).ConfigureAwait(false), 0);
        Require(version is 0 or 0x01000000, AudioAlacFileError.UnsupportedLayout);
        var time = await source.PrefixAsync(mdhd, version == 0 ? 24 : 36, token).ConfigureAwait(false);
        uint timescale = U32(time, version == 0 ? 12 : 20);
        long duration = version == 0 ? U32(time, 16) : U64(time, 24);
        var info = await source.ChildrenAsync(Single(media, "minf"), token).ConfigureAwait(false);
        var references = await source.ChildrenAsync(Single(info, "dinf"), token).ConfigureAwait(false);
        var dref = Single(references, "dref");
        var referenceHeader = await source.PrefixAsync(dref, 8, token).ConfigureAwait(false);
        Require(U32(referenceHeader, 0) == 0 && U32(referenceHeader, 4) == 1, AudioAlacFileError.UnsupportedLayout);
        var urls = await source.BoxesAsync(dref.Start + 8, dref.End, token).ConfigureAwait(false);
        var url = Single(urls, "url ", AudioAlacFileError.UnsupportedLayout);
        Require(urls.Count == 1 && url.Length == 4, AudioAlacFileError.UnsupportedLayout);
        Require(U32(await source.PrefixAsync(url, 4, token).ConfigureAwait(false), 0) == 1, AudioAlacFileError.UnsupportedLayout);
        var table = await source.ChildrenAsync(Single(info, "stbl"), token).ConfigureAwait(false);
        string[] unsupported = ["ctts", "cslg", "stz2", "senc", "saiz", "saio", "sbgp", "sgpd"];
        Require(!table.Any(b => unsupported.Contains(b.Type)), AudioAlacFileError.UnsupportedLayout);
        var stsd = Single(table, "stsd");
        var descriptions = await source.PrefixAsync(stsd, 8, token).ConfigureAwait(false);
        Require(U32(descriptions, 0) == 0 && U32(descriptions, 4) == 1, AudioAlacFileError.UnsupportedLayout);
        var entries = await source.BoxesAsync(stsd.Start + 8, stsd.End, token).ConfigureAwait(false);
        var entry = Single(entries, "alac", AudioAlacFileError.UnsupportedEncoding);
        Require(entries.Count == 1, AudioAlacFileError.UnsupportedLayout);
        var audio = await source.PrefixAsync(entry, 28, token).ConfigureAwait(false);
        Require(audio.Take(6).All(x => x == 0) && U16(audio, 6) == 1 && U16(audio, 8) == 0, AudioAlacFileError.UnsupportedLayout);
        var extensions = await source.BoxesAsync(entry.Start + 28, entry.End, token).ConfigureAwait(false);
        Require(!extensions.Any(b => b.Type == "sinf"), AudioAlacFileError.UnsupportedEncoding);
        var config = Single(extensions, "alac");
        Require(config.Length is 28 or 52, AudioAlacFileError.UnsupportedEncoding);
        var cookie = await source.PrefixAsync(config, (int)config.Length, token).ConfigureAwait(false);
        Require(U32(cookie, 0) == 0 && cookie[8] == 0, AudioAlacFileError.UnsupportedEncoding);
        uint maximumFrames = U32(cookie, 4), maximumBytes = U32(cookie, 16), rate = U32(cookie, 24);
        byte bits = cookie[9], channels = cookie[13];
        Require(maximumFrames is >= 1 and <= 65_536 && maximumBytes <= MaximumPacketBytes, AudioAlacFileError.MetadataLimit);
        Require(bits is 16 or 20 or 24 or 32, AudioAlacFileError.UnsupportedEncoding);
        Require(channels is 1 or 2, AudioAlacFileError.UnsupportedLayout);
        Require(rate > 0 && timescale == rate && duration > 0);
        Require((ulong)duration <= (ulong)rate * 14_400, AudioAlacFileError.MetadataLimit);
        var channelBoxes = extensions.Where(b => b.Type == "chan").ToArray();
        Require(channelBoxes.Length <= 1 && (config.Length != 52 || channelBoxes.Length == 0), AudioAlacFileError.UnsupportedLayout);
        if (config.Length == 52)
        {
            Require(U32(cookie, 28) == 24 && FourCC(cookie, 32) == "chan");
            ValidateLayout(cookie.AsSpan(36, 16), channels);
        }
        if (channelBoxes.Length == 1)
        {
            Require(channelBoxes[0].Length == 16, AudioAlacFileError.UnsupportedLayout);
            ValidateLayout(await source.PrefixAsync(channelBoxes[0], 16, token).ConfigureAwait(false), channels);
        }
        var timing = await source.TableAsync(Single(table, "stts"), 8, token).ConfigureAwait(false);
        var stsz = Single(table, "stsz");
        var sizesHeader = await source.PrefixAsync(stsz, 12, token).ConfigureAwait(false);
        uint fixedBytes = U32(sizesHeader, 4); long packets = U32(sizesHeader, 8);
        Require(U32(sizesHeader, 0) == 0 && packets is >= 1 and <= MaximumPackets && fixedBytes <= MaximumPacketBytes &&
            stsz.Length == 12 + (fixedBytes == 0 ? packets * 4 : 0));
        AudioAlacTable? sizes = fixedBytes == 0 ? new(stsz.Start + 12, packets, 4) : null;
        var offsetBoxes = table.Where(b => b.Type is "stco" or "co64").ToArray();
        Require(offsetBoxes.Length == 1, AudioAlacFileError.UnsupportedLayout);
        var offsets = await source.TableAsync(offsetBoxes[0], offsetBoxes[0].Type == "co64" ? 8 : 4, token).ConfigureAwait(false);
        var runs = await source.TableAsync(Single(table, "stsc"), 12, token).ConfigureAwait(false);
        Require(offsets.Count <= packets && runs.Count <= offsets.Count);
        var mediaData = top.Where(b => b.Type == "mdat" && b.Length > 0).ToArray(); Require(mediaData.Length > 0);
        AudioStreamingPcmFormat format;
        try
        {
            format = new(rate, channels, bits == 16 ? AudioStreamingEncoding.Signed16 :
                bits == 32 ? AudioStreamingEncoding.Signed32 : AudioStreamingEncoding.Signed24, bits, channels == 1 ? 4u : 3u);
        }
        catch (InvalidDataException) { throw new AudioAlacFileException(AudioAlacFileError.Malformed); }
        var index = new AudioAlacIndex(duration, packets, maximumFrames, maximumBytes == 0 ? null : maximumBytes,
            fixedBytes == 0 ? null : fixedBytes, timing, sizes, offsets, runs, mediaData);
        var cursor = new AudioAlacPacketCursor(index); long encodedBytes = 0;
        while (await cursor.NextAsync(source.BytesAsync, token.ThrowIfCancellationRequested, token).ConfigureAwait(false) is { } packet)
            encodedBytes += packet.ByteCount; // Packet and byte limits bound the sum below Int64.MaxValue.
        token.ThrowIfCancellationRequested();
        return new(format, encodedBytes, cookie.AsSpan(4, 24).ToArray(), index);
    }

    private static AudioAlacBox Single(IReadOnlyList<AudioAlacBox> boxes, string type,
        AudioAlacFileError error = AudioAlacFileError.Malformed)
    {
        var matches = boxes.Where(b => b.Type == type).ToArray(); Require(matches.Length == 1, error); return matches[0];
    }
    private static void ValidateLayout(ReadOnlySpan<byte> bytes, byte channels) => Require(U32(bytes, 0) == 0 &&
        U32(bytes, 4) == ((99u + channels) << 16) + channels && U32(bytes, 8) == 0 && U32(bytes, 12) == 0,
        AudioAlacFileError.UnsupportedLayout);
    internal static void Require(bool condition, AudioAlacFileError error = AudioAlacFileError.Malformed)
    { if (!condition) throw new AudioAlacFileException(error); }
    internal static ushort U16(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2));
    internal static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset, 4));
    internal static long U64(ReadOnlySpan<byte> bytes, int offset)
    {
        ulong value = BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(offset, 8));
        Require(value <= long.MaxValue, AudioAlacFileError.Oversized); return (long)value;
    }
    internal static string FourCC(byte[] bytes, int offset) => Encoding.Latin1.GetString(bytes, offset, 4);
}

internal sealed record AudioAlacBox(string Type, long Start, long End) { internal long Length => End - Start; }
internal sealed record AudioAlacTable(long Start, long Count, int Stride);
internal sealed record AudioAlacRun(long FirstChunk, uint PacketsPerChunk);
internal sealed record AudioAlacIndex(long Frames, long Packets, uint MaximumFrames, uint? MaximumBytes,
    uint? FixedBytes, AudioAlacTable Timing, AudioAlacTable? Sizes, AudioAlacTable Offsets, AudioAlacTable Runs,
    AudioAlacBox[] Media)
{
    internal bool ContainsMedia(long offset, long count)
    {
        int lower = 0, upper = Media.Length;
        while (lower < upper)
        {
            int middle = lower + (upper - lower) / 2;
            if (Media[middle].Start <= offset) lower = middle + 1; else upper = middle;
        }
        if (lower == 0) return false;
        var range = Media[lower - 1]; return offset <= range.End && count <= range.End - offset;
    }
}

internal sealed class AudioAlacSource(long size, Func<long, int, CancellationToken, Task<byte[]>> read)
{
    private int _boxes;
    private long _metadataBytes;
    internal async Task<byte[]> BytesAsync(long offset, int count, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        AudioAlacFile.Require(count is >= 1 and <= AudioAlacFile.MaximumReadBytes && offset >= 0 && offset <= size &&
            count <= size - offset, AudioAlacFileError.Truncated);
        AudioAlacFile.Require(count <= AudioAlacFile.MaximumMetadataBytes - _metadataBytes, AudioAlacFileError.MetadataLimit);
        _metadataBytes += count;
        var value = await read(offset, count, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        AudioAlacFile.Require(value.Length >= count, AudioAlacFileError.Truncated);
        AudioAlacFile.Require(value.Length == count, AudioAlacFileError.InvalidReadLength);
        return value;
    }
    internal Task<byte[]> PrefixAsync(AudioAlacBox box, int count, CancellationToken token)
    {
        AudioAlacFile.Require(count <= box.Length, AudioAlacFileError.Truncated);
        return BytesAsync(box.Start, count, token);
    }
    internal Task<List<AudioAlacBox>> ChildrenAsync(AudioAlacBox box, CancellationToken token) => BoxesAsync(box.Start, box.End, token);
    internal async Task<List<AudioAlacBox>> BoxesAsync(long start, long end, CancellationToken token)
    {
        List<AudioAlacBox> result = [];
        for (long offset = start; offset < end;)
        {
            AudioAlacFile.Require(++_boxes <= AudioAlacFile.MaximumBoxes, AudioAlacFileError.MetadataLimit);
            AudioAlacFile.Require(end - offset >= 8, AudioAlacFileError.Truncated);
            var header = await BytesAsync(offset, 8, token).ConfigureAwait(false);
            long length = AudioAlacFile.U32(header, 0), headerLength = 8;
            if (length == 1)
            {
                AudioAlacFile.Require(end - offset >= 16, AudioAlacFileError.Truncated);
                length = AudioAlacFile.U64(await BytesAsync(offset + 8, 8, token).ConfigureAwait(false), 0); headerLength = 16;
            }
            else if (length == 0) length = end - offset;
            AudioAlacFile.Require(length >= headerLength);
            AudioAlacFile.Require(length <= end - offset, AudioAlacFileError.Truncated);
            result.Add(new(AudioAlacFile.FourCC(header, 4), offset + headerLength, offset + length)); offset += length;
        }
        return result;
    }
    internal async Task<AudioAlacTable> TableAsync(AudioAlacBox box, int stride, CancellationToken token)
    {
        var header = await PrefixAsync(box, 8, token).ConfigureAwait(false); long count = AudioAlacFile.U32(header, 4);
        AudioAlacFile.Require(AudioAlacFile.U32(header, 0) == 0 && count is >= 1 and <= AudioAlacFile.MaximumPackets &&
            box.Length == 8 + count * stride);
        return new(box.Start + 8, count, stride);
    }
}

internal sealed class AudioAlacPage(AudioAlacTable table)
{
    private long? _first;
    private byte[] _cached = [];
    private async Task<int> FieldAsync(long index, int offset, int width,
        Func<long, int, CancellationToken, Task<byte[]>> read, Action check, CancellationToken token)
    {
        check();
        AudioAlacFile.Require(index >= 0 && index < table.Count && offset >= 0 && width > 0 && offset <= table.Stride - width);
        long perPage = AudioAlacFile.MaximumReadBytes / table.Stride, block = index / perPage * perPage;
        if (_first != block)
        {
            int count = checked((int)Math.Min(perPage, table.Count - block) * table.Stride);
            var data = await read(table.Start + block * table.Stride, count, token).ConfigureAwait(false); check();
            AudioAlacFile.Require(data.Length >= count, AudioAlacFileError.Truncated);
            AudioAlacFile.Require(data.Length == count, AudioAlacFileError.InvalidReadLength);
            _cached = data.ToArray(); _first = block;
        }
        return checked((int)(index - block) * table.Stride + offset);
    }
    internal async Task<uint> U32Async(long index, int offset, Func<long, int, CancellationToken, Task<byte[]>> read,
        Action check, CancellationToken token)
    {
        int at = await FieldAsync(index, offset, 4, read, check, token).ConfigureAwait(false);
        return AudioAlacFile.U32(_cached, at);
    }
    internal async Task<long> U64Async(long index, Func<long, int, CancellationToken, Task<byte[]>> read,
        Action check, CancellationToken token)
    {
        int at = await FieldAsync(index, 0, 8, read, check, token).ConfigureAwait(false);
        return AudioAlacFile.U64(_cached, at);
    }
}
