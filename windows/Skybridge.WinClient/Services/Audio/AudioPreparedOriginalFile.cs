namespace Skybridge.WinClient.Services.Audio;

internal sealed class AudioOriginalFilePreparationException(string message) : IOException(message);

// Constructed only from the exact verified artifact. Compressed-file witnesses
// require a complete decode before output opens and cannot be paired with another file.
internal abstract class AudioPreparedOriginalFile
{
    internal static readonly TimeSpan MaximumPreparationTime = TimeSpan.FromSeconds(180);
    internal const long MaximumSourceSeconds = 14_400;
    internal AudioStreamingPcmFormat Format { get; }
    internal long FrameCount { get; }
    private AudioPreparedOriginalFile(AudioStreamingPcmFormat format, long frames) { Format = format; FrameCount = frames; }
    internal abstract ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
        CancellationToken token, TimeProvider time, Action onStarted, Action<long>? onOutputProgress = null);

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
            if (signature.AsSpan().SequenceEqual("RIFF"u8))
            {
                var wave = await AudioWavePcmFile.InspectAsync(artifact.Length, Read, token).ConfigureAwait(false);
                Check(); return new Wave(artifact, wave);
            }
            limit = MaximumPreparationTime; Check();
            if (signature.AsSpan().SequenceEqual("fLaC"u8))
            {
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
            }
            // ISO BMFF permits boxes before ftyp. The bounded inspector must prove
            // an actual ALAC track; a filename, MIME type or M4A brand is insufficient.
            var alac = await AudioAlacFile.InspectAsync(artifact.Length, Read, token).ConfigureAwait(false);
            Check();
            if (!AudioAlacNative.IsPackaged) throw new AudioOriginalFilePreparationException("The strict ALAC decoder is not packaged.");
            using var alacDecoder = new AudioAlacPcmDecoder(Read, alac);
            while (true)
            {
                Check();
                if (alacDecoder.Next(Check, token) is AudioAlacDecodeStep.Complete completed)
                {
                    Check(); return new Alac(artifact, alac, completed.Receipt);
                }
            }
        }, token);
    }

    private sealed class Wave(AudioOriginalFileArtifact artifact, AudioWavePcmMetadata metadata)
        : AudioPreparedOriginalFile(metadata.Format, metadata.FrameCount)
    {
        internal override ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
            CancellationToken token, TimeProvider time, Action onStarted, Action<long>? onOutputProgress = null) =>
            AudioFilePcmPlayback.Play(artifact, metadata, output, requireAuthorization, token, time, onStarted, onOutputProgress);
    }
    private sealed class Flac(AudioOriginalFileArtifact artifact, AudioFlacMetadata metadata, AudioFlacDecodeReceipt receipt)
        : AudioPreparedOriginalFile(metadata.DecodedFormat, checked((long)receipt.SourceFrames))
    {
        internal override ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
            CancellationToken token, TimeProvider time, Action onStarted, Action<long>? onOutputProgress = null) =>
            AudioFilePcmPlayback.PlaySource(Format, FrameCount,
                cancellation =>
                {
                    cancellation.ThrowIfCancellationRequested(); requireAuthorization();
                    return Task.FromResult<IAudioFilePcmReader>(AudioDecodedFileReadSession.Flac(artifact, metadata, receipt, requireAuthorization));
                }, output, requireAuthorization, token, time, onStarted, onOutputProgress);
    }
    private sealed class Alac(AudioOriginalFileArtifact artifact, AudioAlacMetadata metadata, AudioAlacDecodeReceipt receipt)
        : AudioPreparedOriginalFile(metadata.DecodedFormat, checked((long)receipt.SourceFrames))
    {
        internal override ExclusivePcmPlaybackReceipt Play(ExclusivePcmOutput output, Action requireAuthorization,
            CancellationToken token, TimeProvider time, Action onStarted, Action<long>? onOutputProgress = null) =>
            AudioFilePcmPlayback.PlaySource(Format, FrameCount,
                cancellation =>
                {
                    cancellation.ThrowIfCancellationRequested(); requireAuthorization();
                    return Task.FromResult<IAudioFilePcmReader>(AudioDecodedFileReadSession.Alac(artifact, metadata, receipt, requireAuthorization));
                }, output, requireAuthorization, token, time, onStarted, onOutputProgress);
    }
}
