using System.Buffers.Binary;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;

namespace Skybridge.WinClient.Services.Audio;

internal sealed class AudioFilePcmPlaybackException(AudioStreamingStopReason reason, string message)
    : IOException(message)
{
    internal AudioStreamingStopReason Reason { get; } = reason;
}

internal interface IAudioFilePcmReader : IDisposable
{
    Task<byte[]> ReadAsync(long offset, int count, CancellationToken token);
    Task FinishAsync(CancellationToken token);
}

// Call and finish on the thread that opened output. The caller owns the artifact and,
// on failure, the output's final disposal. Successful tail completion disposes output.
internal static class AudioFilePcmPlayback
{
    internal const int MaximumBlockBytes = 65_536;
    internal const int PrefetchBlocks = 2;
    private static readonly TimeSpan ProgressTimeout = TimeSpan.FromSeconds(5);

    public static ExclusivePcmPlaybackReceipt Play(AudioOriginalFileArtifact artifact,
        AudioWavePcmMetadata metadata, ExclusivePcmOutput output, Action requireAuthorization,
        CancellationToken token, TimeProvider? time = null, Action? onStarted = null)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        return PlayCore(artifact.Length, artifact.InspectWaveAsync, artifact.ReadAsync,
            metadata, output, requireAuthorization, token, time ?? TimeProvider.System, onStarted);
    }

    // Controlled read boundary for contract tests. Each read transfers one exact, owned
    // byte array; the callback must not mutate it after returning. Production uses the
    // verified private artifact above, never a URI/path or an unverified file reader.
    internal static ExclusivePcmPlaybackReceipt Play(long fileSize,
        Func<long, int, CancellationToken, Task<byte[]>> read, AudioWavePcmMetadata metadata,
        ExclusivePcmOutput output, Action requireAuthorization, CancellationToken token, TimeProvider? time = null,
        Action? onStarted = null)
    {
        ArgumentNullException.ThrowIfNull(read);
        return PlayCore(fileSize, cancellation => AudioWavePcmFile.InspectAsync(fileSize, read, cancellation),
            read, metadata, output, requireAuthorization, token, time ?? TimeProvider.System, onStarted);
    }

    private static ExclusivePcmPlaybackReceipt PlayCore(long fileSize,
        Func<CancellationToken, Task<AudioWavePcmMetadata>> inspect,
        Func<long, int, CancellationToken, Task<byte[]>> read, AudioWavePcmMetadata metadata,
        ExclusivePcmOutput output, Action requireAuthorization, CancellationToken token, TimeProvider time, Action? onStarted)
    {
        ArgumentNullException.ThrowIfNull(metadata); ArgumentNullException.ThrowIfNull(metadata.Format);
        if (fileSize < 0 || metadata.PcmByteOffset < 0 || metadata.PcmByteCount < 0 ||
            metadata.PcmByteOffset > fileSize || metadata.PcmByteCount > fileSize - metadata.PcmByteOffset ||
            metadata.PcmByteCount % metadata.Format.BytesPerFrame != 0)
            throw new InvalidDataException("PCM extent is outside the verified file or contains a partial frame.");
        return PlaySource(metadata.Format, metadata.FrameCount, async cancellation =>
        {
            var actual = await inspect(cancellation).ConfigureAwait(false);
            if (actual != metadata) throw new InvalidDataException("The file declaration does not belong to this verified source.");
            return new WaveReader(read, metadata.PcmByteOffset);
        }, output, requireAuthorization, token, time, onStarted);
    }

    internal static ExclusivePcmPlaybackReceipt PlaySource(AudioStreamingPcmFormat format, long frameCount,
        Func<CancellationToken, Task<IAudioFilePcmReader>> openSource, ExclusivePcmOutput output,
        Action requireAuthorization, CancellationToken token, TimeProvider time, Action? onStarted)
    {
        ArgumentNullException.ThrowIfNull(format); ArgumentNullException.ThrowIfNull(openSource);
        ArgumentNullException.ThrowIfNull(output); ArgumentNullException.ThrowIfNull(requireAuthorization);
        RequireCurrent();
        if (frameCount < 0) throw new InvalidDataException("A PCM source cannot declare a negative extent.");
        long totalBytes = checked(frameCount * format.BytesPerFrame);
        if (format.RequireExactOutputFormat() != output.Format)
            throw new InvalidDataException("Prepared output differs from the declared file format.");
        if (output.State != ExclusivePcmOutputState.Initialized || output.SubmittedFrames != 0)
            throw new InvalidOperationException("File playback requires a fresh prepared output.");
        var initial = output.ObserveProgress(); // Also enforces native thread ownership.
        if (initial.SubmittedSourceFrames != 0 || initial.QueuedFrames != 0 || initial.DevicePosition != 0)
            throw new InvalidDataException("Fresh file output already contains samples or device progress.");
        int frameBytes = checked((int)format.BytesPerFrame);
        int blockBytes = MaximumBlockBytes - MaximumBlockBytes % frameBytes;
        if (blockBytes == 0) throw new InvalidDataException("A source frame exceeds the file prefetch limit.");

        var queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(PrefetchBlocks)
        {
            SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false
        });
        using var stop = new CancellationTokenSource();
        Exception? cancellationFailure = null;
        using var cancellation = token.Register(() =>
        {
            try { stop.Cancel(); }
            catch (Exception error) { Volatile.Write(ref cancellationFailure, error); }
        });
        // No synchronous portion of a callback runs on the native thread. Reserving
        // capacity BEFORE each read limits queued + in-flight blocks to two. The
        // native loop holds at most one further block, also <=64KiB, with no copy.
        var producer = Task.Run(ProduceAsync);
        ExclusivePcmPlaybackReceipt? receipt = null;
        Exception? primary = null;
        var cleanup = new List<Exception>();
        try { receipt = Pump(); }
        catch (Exception error) { primary = error; }
        if (primary is not null)
        {
            // A noncooperative disk read must not keep already queued audio playing
            // after cancellation. Stop on this native thread, but leave Dispose to
            // the outer owner. Output methods may already have failed and disposed.
            if (output.State is ExclusivePcmOutputState.Initialized or ExclusivePcmOutputState.Primed or
                ExclusivePcmOutputState.Running or ExclusivePcmOutputState.InputEnded or ExclusivePcmOutputState.EndpointDrained)
            {
                try { output.Stop(); }
                catch (Exception error) { cleanup.Add(error); }
            }
            try { stop.Cancel(); }
            catch (Exception error) { cleanup.Add(error); }
        }
        // This join occurs only after native playback has finished or been stopped.
        // A read that ignores cancellation remains owned; no detached producer or
        // timeout is used to pretend that its resource has been released.
        try { producer.GetAwaiter().GetResult(); }
        catch (Exception error)
        {
            bool cancelledByFailure = primary is not null && stop.IsCancellationRequested &&
                error is OperationCanceledException cancelled && cancelled.CancellationToken == stop.Token && cancelled.InnerException is null;
            if (!cancelledByFailure && !Includes(primary, error) && !cleanup.Any(existing => Includes(existing, error))) cleanup.Add(error);
        }
        // Dispose waits for a concurrently running cancellation callback. Its
        // failures cannot be lost merely because the caller initiated cancellation.
        cancellation.Dispose();
        if (Volatile.Read(ref cancellationFailure) is { } signalFailure &&
            !Includes(primary, signalFailure) && !cleanup.Any(existing => Includes(existing, signalFailure)))
            cleanup.Add(signalFailure);
        while (queue.Reader.TryRead(out _)) { }
        if (cleanup.Count != 0)
        {
            if (primary is not null) cleanup.Insert(0, primary);
            throw new AggregateException("File playback failed while retaining producer or native cleanup errors.", cleanup);
        }
        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
        return receipt ?? throw new InvalidOperationException("File playback ended without a native completion receipt.");

        async Task ProduceAsync()
        {
            try
            {
                CheckProducer();
                using var source = await openSource(stop.Token).ConfigureAwait(false);
                CheckProducer();
                long offset = 0, remaining = totalBytes;
                while (remaining != 0)
                {
                    if (!await queue.Writer.WaitToWriteAsync(stop.Token).ConfigureAwait(false))
                        throw new IOException("The file prefetch queue ended before its source.");
                    CheckProducer();
                    int count = (int)Math.Min(remaining, blockBytes);
                    var bytes = await source.ReadAsync(offset, count, stop.Token).ConfigureAwait(false);
                    CheckProducer();
                    if (bytes is null || bytes.Length != count)
                        throw new InvalidDataException("File PCM read did not return the exact verified range.");
                    if (!queue.Writer.TryWrite(bytes))
                        throw new IOException("The single file producer lost its reserved queue capacity.");
                    offset += count; remaining -= count;
                }
                CheckProducer();
                await source.FinishAsync(stop.Token).ConfigureAwait(false);
                CheckProducer();
            }
            finally { queue.Writer.TryComplete(); }
        }

        void CheckProducer() { stop.Token.ThrowIfCancellationRequested(); requireAuthorization(); stop.Token.ThrowIfCancellationRequested(); }
        void RequireCurrent() { token.ThrowIfCancellationRequested(); requireAuthorization(); token.ThrowIfCancellationRequested(); }

        ExclusivePcmPlaybackReceipt Pump()
        {
            bool playing = false;
            byte[]? current = null;
            int position = 0;
            long accepted = 0, lastProgress = time.GetTimestamp();
            ulong lastRetired = 0;
            while (true)
            {
                RequireCurrent();
                if (producer.IsCompleted) producer.GetAwaiter().GetResult();
                CheckProgressDeadline();
                var progress = output.ObserveProgress();
                RequireCurrent(); CheckProgressDeadline();
                if (progress.SubmittedSourceFrames != (ulong)(accepted / frameBytes))
                    throw new AudioFilePcmPlaybackException(AudioStreamingStopReason.OutputLost, "Native acceptance differs from the file extent.");
                if (progress.RetiredSourceFrames > lastRetired)
                {
                    lastRetired = progress.RetiredSourceFrames; lastProgress = time.GetTimestamp();
                }
                if (playing && progress.QueuedFrames == 0 && accepted < totalBytes)
                    throw new AudioFilePcmPlaybackException(AudioStreamingStopReason.OutputLost,
                        "The output queue exhausted before the remaining file samples arrived.");
                if (current is null && queue.Reader.TryRead(out var next))
                {
                    RequireFinite(next, format); current = next; position = 0;
                }
                if (current is null && producer.IsCompleted)
                {
                    producer.GetAwaiter().GetResult();
                    // Completion can race the preceding empty TryRead: the producer
                    // may have published its final block between those observations.
                    if (queue.Reader.TryRead(out var final))
                    {
                        RequireFinite(final, format); current = final; position = 0;
                        continue;
                    }
                    if (accepted != totalBytes)
                        throw new InvalidDataException("File prefetch ended before all declared samples were submitted.");
                    RequireCurrent(); output.FinishInput(checked((ulong)frameCount));
                    if (!playing && accepted != 0) StartOutput();
                    var completed = output.CompleteAfterDeviceTail(ProgressTimeout, token, RequireCurrent);
                    if (completed.SourceFrames != (ulong)frameCount)
                        throw new AudioFilePcmPlaybackException(AudioStreamingStopReason.OutputLost, "Native completion differs from the declared file extent.");
                    return completed;
                }
                uint available = output.BufferFrames - progress.QueuedFrames;
                if (current is not null && available != 0)
                {
                    int count = checked((int)Math.Min((long)available * frameBytes, current.Length - position));
                    RequireCurrent(); CheckProgressDeadline(); output.Submit(current, position, count, requireQueuedFrames: playing);
                    accepted += count; position += count; lastProgress = time.GetTimestamp();
                    if (position == current.Length) current = null;
                    continue;
                }
                // Prime the full endpoint buffer (or seal a shorter whole file)
                // before Start. Neither prefill nor a short final packet adds zeros.
                if (!playing && available == 0) StartOutput();
                RequireCurrent(); output.Pace(token);
            }

            void CheckProgressDeadline()
            {
                var elapsed = time.GetElapsedTime(lastProgress);
                if (elapsed < TimeSpan.Zero || elapsed >= ProgressTimeout)
                    throw new TimeoutException("File playback made no source or endpoint progress within five seconds.");
            }
            void StartOutput()
            {
                RequireCurrent(); output.Start(); playing = true;
                onStarted?.Invoke(); // Exactly once, after native Start succeeds; never for empty input.
            }
        }
    }

    private sealed class WaveReader(Func<long, int, CancellationToken, Task<byte[]>> read, long pcmOffset) : IAudioFilePcmReader
    {
        public Task<byte[]> ReadAsync(long offset, int count, CancellationToken token) => read(checked(pcmOffset + offset), count, token);
        public Task FinishAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public void Dispose() { } // Borrows its caller-owned verified artifact; owns no native state.
    }

    private static void RequireFinite(ReadOnlySpan<byte> bytes, AudioStreamingPcmFormat format)
    {
        if (!format.FloatingPoint) return;
        int width = format.ContainerBits / 8;
        for (int offset = 0; offset < bytes.Length; offset += width)
        {
            bool finite = width == 4
                ? (BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]) & 0x7f800000U) != 0x7f800000U
                : (BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]) & 0x7ff0000000000000UL) != 0x7ff0000000000000UL;
            if (!finite) throw new AudioFilePcmPlaybackException(AudioStreamingStopReason.UnsupportedSource,
                "File PCM contains a non-finite floating-point sample.");
        }
    }

    private static bool Includes(Exception? parent, Exception child) => ReferenceEquals(parent, child) ||
        parent is AggregateException aggregate && aggregate.InnerExceptions.Any(error => Includes(error, child)) ||
        parent?.InnerException is { } inner && Includes(inner, child);
}
