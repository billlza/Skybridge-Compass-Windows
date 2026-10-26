namespace Skybridge.WinClient.Services.Audio;

// The file-prefetch producer owns reads, finish and disposal sequentially. Retains
// one native-decoded frame (FLAC <=2,097,120 bytes; ALAC <=524,288 bytes), and lends
// <=64 KiB whole-frame blocks to the existing bounded playback pump.
internal sealed class AudioDecodedFileReadSession : IAudioFilePcmReader
{
    private sealed record Frame(ulong FirstIndex, byte[] Bytes);
    // Null is only a decoder's clean EOF with a receipt equal to the prepass.
    private readonly Func<CancellationToken, Frame?> _next;
    private readonly IDisposable _decoder;
    private readonly Action _authorize;
    private readonly ulong _frames;
    private readonly int _frameBytes;
    private byte[] _pending = [];
    private int _pendingOffset;
    private long _position;
    private bool _closed;

    private AudioDecodedFileReadSession(AudioStreamingPcmFormat format, ulong frames, Action authorize,
        IDisposable decoder, Func<CancellationToken, Frame?> next)
    {
        _frameBytes = checked((int)format.BytesPerFrame); _frames = frames;
        _authorize = authorize; _decoder = decoder; _next = next;
    }
    internal static AudioDecodedFileReadSession Flac(AudioOriginalFileArtifact artifact, AudioFlacMetadata metadata,
        AudioFlacDecodeReceipt expected, Action authorize)
    {
        var decoder = new AudioFlacPcmDecoder(artifact.Length, artifact.ReadAsync, metadata);
        return new(metadata.DecodedFormat, expected.SourceFrames, authorize, decoder, token =>
            decoder.Next(authorize, token) switch
            {
                AudioFlacDecodeStep.Frame frame => new(frame.FirstIndex, frame.Bytes),
                AudioFlacDecodeStep.Complete complete when complete.Receipt == expected => null,
                _ => throw new InvalidDataException("FLAC playback decode differs from the complete validated file.")
            });
    }
    internal static AudioDecodedFileReadSession Alac(AudioOriginalFileArtifact artifact, AudioAlacMetadata metadata,
        AudioAlacDecodeReceipt expected, Action authorize)
    {
        var decoder = new AudioAlacPcmDecoder(artifact.ReadAsync, metadata);
        return new(metadata.DecodedFormat, expected.SourceFrames, authorize, decoder, token =>
            decoder.Next(authorize, token) switch
            {
                AudioAlacDecodeStep.Frame frame => new(frame.FirstIndex, frame.Bytes),
                AudioAlacDecodeStep.Complete complete when complete.Receipt == expected => null,
                _ => throw new InvalidDataException("ALAC playback decode differs from the complete validated file.")
            });
    }
    public Task<byte[]> ReadAsync(long offset, int count, CancellationToken token)
    {
        Check(token);
        if (offset != _position || count is < 1 or > AudioFilePcmPlayback.MaximumBlockBytes || count % _frameBytes != 0 ||
            (ulong)(_position / _frameBytes) > _frames ||
            (ulong)(count / _frameBytes) > _frames - (ulong)(_position / _frameBytes))
            throw new InvalidDataException("Decoded PCM reads must cover a bounded sequential whole-frame extent.");
        var result = new byte[count]; int copied = 0;
        while (copied < count)
        {
            Check(token);
            if (_pendingOffset == _pending.Length)
            {
                _pending = []; _pendingOffset = 0;
                var frame = _next(token);
                if (frame is null || frame.FirstIndex != (ulong)(_position / _frameBytes) ||
                    frame.Bytes.Length == 0 || frame.Bytes.Length % _frameBytes != 0 ||
                    (ulong)(frame.Bytes.Length / _frameBytes) > _frames - frame.FirstIndex)
                    throw new InvalidDataException("Decoding ended or changed sequence before all source samples.");
                _pending = frame.Bytes;
            }
            int length = Math.Min(count - copied, _pending.Length - _pendingOffset);
            _pending.AsSpan(_pendingOffset, length).CopyTo(result.AsSpan(copied));
            copied += length; _pendingOffset += length; _position += length;
        }
        Check(token); return Task.FromResult(result);
    }
    public Task FinishAsync(CancellationToken token)
    {
        Check(token);
        if ((ulong)(_position / _frameBytes) != _frames || _pendingOffset != _pending.Length || _next(token) is not null)
            throw new InvalidDataException("Playback did not consume the complete validated source.");
        Check(token); return Task.CompletedTask;
    }
    private void Check(CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(_closed, this);
        _authorize(); token.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(_closed, this);
    }
    public void Dispose() { _closed = true; _decoder.Dispose(); _pending = []; _pendingOffset = 0; }
}
