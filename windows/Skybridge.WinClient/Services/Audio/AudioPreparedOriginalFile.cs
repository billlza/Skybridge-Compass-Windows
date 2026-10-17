namespace Skybridge.WinClient.Services.Audio;

internal sealed class AudioOriginalFilePreparationException(string message) : IOException(message);

// Constructed only from the exact verified artifact. A FLAC witness requires a
// complete decode before output is opened; it cannot be paired with another file.
internal abstract class AudioPreparedOriginalFile
{
    internal static readonly TimeSpan MaximumPreparationTime = TimeSpan.FromSeconds(180);
    internal const long MaximumSourceSeconds = 14_400;
    internal AudioStreamingPcmFormat Format { get; }
    internal long FrameCount { get; }
    private AudioPreparedOriginalFile(AudioStreamingPcmFormat format, long frames) { Format = format; FrameCount = frames; }
    internal abstract ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
        CancellationToken token, TimeProvider time, Action onStarted);

    internal static Task<AudioPreparedOriginalFile> PrepareAsync(AudioOriginalFileArtifact artifact,
        Action requireAuthorization, CancellationToken token, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(artifact); ArgumentNullException.ThrowIfNull(requireAuthorization);
        long start = time.GetTimestamp();
        // Both synchronous decoder work and the synchronous portion of any source
        // callback run off the UI and dedicated native-output thread.
        return Task.Run<AudioPreparedOriginalFile>(async () =>
        {
            TimeSpan limit = TimeSpan.FromSeconds(10);
            void Check()
            {
                token.ThrowIfCancellationRequested(); requireAuthorization(); token.ThrowIfCancellationRequested();
                var elapsed = time.GetElapsedTime(start);
                if (elapsed < TimeSpan.Zero || elapsed >= limit) throw new TimeoutException("Original audio validation exceeded its deadline.");
            }
            async Task<byte[]> Read(long offset, int count, CancellationToken cancellation)
            {
                Check(); var bytes = await artifact.ReadAsync(offset, count, cancellation).ConfigureAwait(false); Check(); return bytes;
            }
            Check();
            if (artifact.Length < 4) throw new AudioOriginalFilePreparationException("Original audio has no complete container signature.");
            var signature = await Read(0, 4, token).ConfigureAwait(false);
            if (!signature.AsSpan().SequenceEqual("fLaC"u8))
            {
                var wave = await AudioWavePcmFile.InspectAsync(artifact.Length, Read, token).ConfigureAwait(false);
                Check(); return new Wave(artifact, wave);
            }
            limit = MaximumPreparationTime; Check();
            if (!AudioFlacNative.IsPackaged) throw new AudioOriginalFilePreparationException("The strict FLAC decoder is not packaged.");
            var flac = await AudioFlacFile.InspectAsync(artifact.Length, Read, token).ConfigureAwait(false);
            if (flac.TotalFrames is not { } frames || frames <= 0 || frames > flac.DecodedFormat.SampleRate * MaximumSourceSeconds)
                throw new AudioOriginalFilePreparationException("FLAC must declare a positive duration no longer than four hours.");
            using var decoder = new AudioFlacPcmDecoder(artifact.Length, Read, flac);
            while (true)
            {
                Check();
                if (decoder.Next(Check, token) is AudioFlacDecodeStep.Complete completed)
                {
                    Check(); return new Flac(artifact, flac, completed.Receipt);
                }
                // Discard each verified PCM frame. Never cache a whole decoded song.
            }
        }, token);
    }

    private sealed class Wave(AudioOriginalFileArtifact artifact, AudioWavePcmMetadata metadata)
        : AudioPreparedOriginalFile(metadata.Format, metadata.FrameCount)
    {
        internal override ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
            CancellationToken token, TimeProvider time, Action onStarted) =>
            AudioFilePcmPlayback.Play(artifact, metadata, output, requireAuthorization, token, time, onStarted);
    }
    private sealed class Flac(AudioOriginalFileArtifact artifact, AudioFlacMetadata metadata, AudioFlacDecodeReceipt receipt)
        : AudioPreparedOriginalFile(metadata.DecodedFormat, checked((long)receipt.SourceFrames))
    {
        internal override ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
            CancellationToken token, TimeProvider time, Action onStarted) =>
            AudioFilePcmPlayback.PlaySource(Format, FrameCount,
                cancellation =>
                {
                    cancellation.ThrowIfCancellationRequested(); requireAuthorization();
                    return Task.FromResult<IAudioFilePcmReader>(new AudioFlacPcmReadSession(artifact, metadata, receipt, requireAuthorization));
                }, output, requireAuthorization, token, time, onStarted);
    }
}

// One sequential producer owns this adapter. It retains at most one decoded
// frame (<=2,097,120 bytes) and lends <=64 KiB whole-frame blocks to the pump.
internal sealed class AudioFlacPcmReadSession : IAudioFilePcmReader
{
    private readonly AudioFlacPcmDecoder _decoder;
    private readonly AudioFlacDecodeReceipt _expected;
    private readonly Action _authorize;
    private readonly int _frameBytes;
    private byte[] _pending = [];
    private int _pendingOffset;
    private long _position;
    internal AudioFlacPcmReadSession(AudioOriginalFileArtifact artifact, AudioFlacMetadata metadata,
        AudioFlacDecodeReceipt expected, Action authorize)
    {
        _decoder = new(artifact.Length, artifact.ReadAsync, metadata);
        _expected = expected; _authorize = authorize; _frameBytes = checked((int)metadata.DecodedFormat.BytesPerFrame);
    }
    public Task<byte[]> ReadAsync(long offset, int count, CancellationToken token)
    {
        Check(token);
        if (offset != _position || count is < 1 or > AudioFilePcmPlayback.MaximumBlockBytes || count % _frameBytes != 0 ||
            (ulong)(_position / _frameBytes) > _expected.SourceFrames ||
            (ulong)(count / _frameBytes) > _expected.SourceFrames - (ulong)(_position / _frameBytes))
            throw new InvalidDataException("FLAC PCM reads must cover a bounded sequential whole-frame extent.");
        var result = new byte[count]; int copied = 0;
        while (copied < count)
        {
            Check(token);
            if (_pendingOffset == _pending.Length)
            {
                _pending = []; _pendingOffset = 0;
                if (_decoder.Next(_authorize, token) is not AudioFlacDecodeStep.Frame frame ||
                    frame.FirstIndex != (ulong)(_position / _frameBytes))
                    throw new InvalidDataException("FLAC decoding ended or changed sequence before all source samples.");
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
        if ((ulong)(_position / _frameBytes) != _expected.SourceFrames || _pendingOffset != _pending.Length ||
            _decoder.Next(_authorize, token) is not AudioFlacDecodeStep.Complete completed || completed.Receipt != _expected)
            throw new InvalidDataException("FLAC playback decode differs from the complete validated file.");
        Check(token); return Task.CompletedTask;
    }
    private void Check(CancellationToken token) { token.ThrowIfCancellationRequested(); _authorize(); token.ThrowIfCancellationRequested(); }
    public void Dispose() { _decoder.Dispose(); _pending = []; _pendingOffset = 0; }
}
