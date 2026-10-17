namespace Skybridge.WinClient.Services.Audio;

internal interface IExclusivePcmDevice : IDisposable
{
    IExclusivePcmClient Activate();
}

internal interface IExclusivePcmClient : IDisposable
{
    int IsExactFormatSupported(ExactPcmFormat format);
    int Initialize(ExactPcmFormat format, long bufferDuration100Nanoseconds);
    uint GetBufferFrames();
    int GetStreamLatency(out long latency100Nanoseconds);
    void Prepare();
    uint GetQueuedFrames();
    int GetClockPosition(out ulong position, out ulong frequency);
    void Submit(byte[] bytes, int offset, int count, uint frames);
    void Start();
    void WaitForProgress(TimeSpan delay, CancellationToken cancellationToken);
    void Stop();
}

// A failed open cannot lose the native owners whose release was not confirmed.
// Retain this exception/owner on the original worker; it never authorizes a retry.
internal sealed class ExclusivePcmOpenCleanupException(IEnumerable<Exception> errors,
    IExclusivePcmDevice device, IExclusivePcmClient? client)
    : AggregateException("Output open failed and native release is unconfirmed.", errors)
{
    internal IExclusivePcmDevice RetainedDevice { get; } = device;
    internal IExclusivePcmClient? RetainedClient { get; } = client;
}

internal enum ExclusivePcmOutputState { Initialized, Primed, Running, InputEnded, EndpointDrained, Stopped, Faulted, Disposed, CleanupFailed, Completed }

// Clock positions are device-defined units. No extrapolation or source-frame mapping is implied.
internal readonly record struct ExclusivePcmProgress(ulong SubmittedSourceFrames, ulong RetiredSourceFrames,
    uint QueuedFrames, ulong DevicePosition, ulong DeviceFrequency);
internal sealed record ExclusivePcmEndpointDrain(ulong SourceFrames, ulong DevicePosition, ulong DeviceFrequency);

// Driver-reported tail rendering boundary, NOT an independent DAC/sample-continuity proof.
// A null tail is meaningful only for a source with no submitted frames.
internal sealed record ExclusivePcmTailObservation(long ReportedLatency100Nanoseconds,
    ulong AnchorDevicePosition, ulong FinalDevicePosition, ulong DeviceFrequency, TimeSpan HostElapsed);
internal sealed record ExclusivePcmPlaybackReceipt(ulong SourceFrames, ExclusivePcmTailObservation? Tail);

internal interface IExclusivePcmPacketPort
{
    IntPtr Acquire(uint frames);
    void Copy(byte[] bytes, int offset, IntPtr destination, int count);
    void Release(uint frames);
}

// Non-event WASAPI permits ReleaseBuffer(0) to discard a packet before submission.
// Once a ReleaseBuffer call was attempted, ownership is uncertain on error: never retry it.
internal static class ExclusivePcmPacketWriter
{
    internal static void Write(IExclusivePcmPacketPort port, byte[] bytes, int offset, int count, uint frames)
    {
        var destination = port.Acquire(frames);
        bool releaseAttempted = false;
        try
        {
            if (destination == IntPtr.Zero) throw new IOException("Endpoint returned a null render buffer.");
            port.Copy(bytes, offset, destination, count);
            releaseAttempted = true;
            port.Release(frames);
        }
        catch (Exception failure)
        {
            if (!releaseAttempted)
            {
                try { port.Release(0); }
                catch (Exception cleanup) { throw new AggregateException("PCM packet copy and discard failed.", failure, cleanup); }
            }
            throw;
        }
    }
}

internal static class ExclusivePcmPacketBounds
{
    public static void Validate(int arrayLength, int offset, int count, uint frames, uint capacity, ushort bytesPerFrame)
    {
        if (frames == 0 || frames > capacity || bytesPerFrame == 0 ||
            (long)frames * bytesPerFrame != count || count > ExclusivePcmOutput.MaximumPeriodBytes ||
            offset < 0 || count <= 0 || offset > arrayLength - count)
            throw new ArgumentException("PCM packet must contain whole frames within the initialized native buffer.");
    }
}

// Synchronous, thread-confined owner for non-event exclusive output. No network I/O,
// resampling, padding, implicit retries or shared-mode fallback. EndpointDrained means
// WASAPI reported an empty endpoint queue; it is NOT playbackComplete or a DAC proof.
internal sealed class ExclusivePcmOutput : IDisposable
{
    internal const int MaximumPeriodBytes = 1024 * 1024;
    internal const int MaximumClockReadAttempts = 3;
    private readonly int _threadId = Environment.CurrentManagedThreadId;
    private readonly IExclusivePcmDevice _device;
    private readonly IExclusivePcmClient _client;
    private readonly TimeProvider _time;
    private readonly TimeSpan _pollInterval;
    private bool _startAttempted, _inputEnded, _disposed, _hasClock;
    private ulong _retiredFrames, _lastClockPosition, _clockFrequency;
    public AggregateException? CleanupFailure { get; private set; }

    public ExactPcmFormat Format { get; }
    public uint BufferFrames { get; }
    public int BufferBytes { get; }
    public ulong SubmittedFrames { get; private set; }
    public long ReportedLatency100Nanoseconds { get; }
    public ExclusivePcmOutputState State { get; private set; } = ExclusivePcmOutputState.Initialized;

    private ExclusivePcmOutput(IExclusivePcmDevice device, IExclusivePcmClient client,
        ExactPcmFormat format, uint bufferFrames, long latency100Nanoseconds, TimeProvider time)
    {
        _device = device; _client = client; _time = time;
        Format = format; BufferFrames = bufferFrames; BufferBytes = CheckedBufferBytes(format, bufferFrames);
        ReportedLatency100Nanoseconds = latency100Nanoseconds;
        _pollInterval = TimeSpan.FromTicks(Math.Clamp(PeriodForFrames(format, bufferFrames) / 4, 10_000, 50_000));
    }

    // Takes ownership even on failure. This mode has no event-alignment recovery or mode fallback.
    public static ExclusivePcmOutput Open(IExclusivePcmDevice device, ExactPcmFormat format, uint bufferFrames, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        IExclusivePcmClient? client = null;
        try
        {
            ArgumentNullException.ThrowIfNull(format);
            var duration = PeriodForFrames(format, bufferFrames);
            client = device.Activate();
            RequireSOk(client.IsExactFormatSupported(format), "accept the exact exclusive PCM format");
            RequireSOk(client.Initialize(format, duration), "initialize non-event exclusive PCM output");
            var frames = client.GetBufferFrames(); CheckedBufferBytes(format, frames);
            RequireSOk(client.GetStreamLatency(out long latency), "query maximum output stream latency");
            if (latency < 0 || latency >= TimeSpan.FromSeconds(5).Ticks)
                throw new InvalidDataException("The reported output latency is outside the supported five-second completion budget.");
            client.Prepare();
            return new(device, client, format, frames, latency, time ?? TimeProvider.System);
        }
        catch (Exception failure)
        {
            var errors = new List<Exception> { failure };
            Attempt(() => client?.Dispose(), errors); Attempt(device.Dispose, errors);
            if (errors.Count > 1) throw new ExclusivePcmOpenCleanupException(errors, device, client);
            throw;
        }
    }

    public void Submit(byte[] bytes, int offset, int count, bool requireQueuedFrames = false)
    {
        RequireOpenThread();
        try
        {
            if (_inputEnded || State is not (ExclusivePcmOutputState.Initialized or ExclusivePcmOutputState.Primed or ExclusivePcmOutputState.Running))
                throw new InvalidOperationException("Output input is not open.");
            ArgumentNullException.ThrowIfNull(bytes);
            uint frames = count > 0 ? checked((uint)(count / Format.BytesPerFrame)) : 0;
            ExclusivePcmPacketBounds.Validate(bytes.Length, offset, count, frames, BufferFrames, Format.BytesPerFrame);
            var queued = ReadQueuedFrames();
            // Check the same padding observation used for admission. A prior caller
            // observation cannot authorize filling an already observed playback gap.
            if (requireQueuedFrames && queued == 0)
                throw new IOException("The native output queue exhausted before the next source submission.");
            if (frames > BufferFrames - queued) throw new InvalidOperationException("The native endpoint does not have space for this PCM packet.");
            var nextCount = checked(SubmittedFrames + frames);
            _client.Submit(bytes, offset, count, frames);
            SubmittedFrames = nextCount; // Only a successful ReleaseBuffer advances accepted source count.
            if (!_startAttempted) State = ExclusivePcmOutputState.Primed;
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    public void Start()
    {
        RequireOpenThread();
        try
        {
            if (_startAttempted || SubmittedFrames == 0 || State is not (ExclusivePcmOutputState.Primed or ExclusivePcmOutputState.InputEnded))
                throw new InvalidOperationException("Prime source frames once before starting output.");
            var clock = ReadClock();
            if (clock.Position != 0) throw new InvalidDataException("A new output stream has a nonzero initial device position.");
            _startAttempted = true; _client.Start();
            State = _inputEnded ? ExclusivePcmOutputState.InputEnded : ExclusivePcmOutputState.Running;
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    // A returned capacity is not a reusable grant: Submit always reads padding again.
    public uint WaitForBuffer(TimeSpan timeout, CancellationToken cancellationToken)
    {
        RequireOpenThread();
        try
        {
            if (State != ExclusivePcmOutputState.Running || _inputEnded) throw new InvalidOperationException("Wait for writable space only while receiving input.");
            ValidateTimeout(timeout); var started = _time.GetTimestamp();
            while (true)
            {
                CheckDeadline(started, timeout, cancellationToken);
                var available = BufferFrames - ReadQueuedFrames();
                CheckDeadline(started, timeout, cancellationToken);
                if (available > 0) return available;
                WaitNext(started, timeout, cancellationToken);
            }
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    public ExclusivePcmProgress ObserveProgress()
    {
        RequireOpenThread();
        try
        {
            if (State is ExclusivePcmOutputState.Stopped or ExclusivePcmOutputState.Faulted)
                throw new InvalidOperationException("Output observation requires its active native owner.");
            return ReadProgress();
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    // One short native pacing wait. The outer worker rechecks authority and input
    // between calls; it never blocks that worker on network writes while rendering.
    public void Pace(CancellationToken cancellationToken)
    {
        RequireOpenThread();
        try
        {
            if (State is ExclusivePcmOutputState.Stopped or ExclusivePcmOutputState.Faulted)
                throw new InvalidOperationException("Output pacing requires a prepared or running owner.");
            cancellationToken.ThrowIfCancellationRequested();
            _client.WaitForProgress(TimeSpan.FromMilliseconds(1), cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    public void FinishInput(ulong expectedSourceFrames)
    {
        RequireOpenThread();
        try
        {
            if (_inputEnded || State is not (ExclusivePcmOutputState.Initialized or ExclusivePcmOutputState.Primed or ExclusivePcmOutputState.Running)
                || expectedSourceFrames != SubmittedFrames)
                throw new InvalidOperationException("Finish requires the exact submitted source extent and an open input.");
            _inputEnded = true; State = ExclusivePcmOutputState.InputEnded;
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    // EOF and endpoint consumption are distinct from Stop. Keep the stream alive after this
    // receipt: a higher layer still needs a verified source/device timeline before announcing
    // playbackComplete or choosing when to stop downstream hardware buffers.
    public ExclusivePcmEndpointDrain WaitForEndpointDrain(TimeSpan timeout, CancellationToken cancellationToken)
    {
        RequireOpenThread();
        try
        {
            if (State != ExclusivePcmOutputState.InputEnded || !_inputEnded || (!_startAttempted && SubmittedFrames != 0))
                throw new InvalidOperationException("Endpoint drain requires sealed input and a started nonempty stream.");
            ValidateTimeout(timeout); var started = _time.GetTimestamp();
            while (true)
            {
                CheckDeadline(started, timeout, cancellationToken);
                var progress = ReadProgress();
                CheckDeadline(started, timeout, cancellationToken);
                if (progress.QueuedFrames == 0)
                {
                    State = ExclusivePcmOutputState.EndpointDrained;
                    return new(SubmittedFrames, progress.DevicePosition, progress.DeviceFrequency);
                }
                WaitNext(started, timeout, cancellationToken);
            }
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    // Inference from WASAPI's maximum rendering-latency contract: after a fresh empty
    // endpoint observation, leave this exact stream running for at least that latency.
    // Require BOTH host elapsed time and precise device-clock progress; nominal device
    // frequency ignores drift and cannot alone establish elapsed host time. No source
    // frame -> device-position equivalence is assumed, even following an earlier gap.
    // Higher layers must retain any already detected underrun as failure. This only
    // settles the tail, and returns after Stop and resource cleanup actually succeed.
    public ExclusivePcmPlaybackReceipt CompleteAfterDeviceTail(TimeSpan timeout,
        CancellationToken cancellationToken, Action requireEffectAuthorization)
    {
        RequireOpenThread(); ArgumentNullException.ThrowIfNull(requireEffectAuthorization);
        try
        {
            if (!_inputEnded || State is not (ExclusivePcmOutputState.InputEnded or ExclusivePcmOutputState.EndpointDrained) ||
                (!_startAttempted && SubmittedFrames != 0))
                throw new InvalidOperationException("Tail completion requires sealed source input on its running output owner.");
            ValidateTimeout(timeout); var started = _time.GetTimestamp();
            ExclusivePcmTailObservation? tail = null;
            ExclusivePcmProgress? anchor = null;
            long anchorHost = 0;
            while (true)
            {
                CheckDeadline(started, timeout, cancellationToken); requireEffectAuthorization();
                var progress = ReadProgress();
                CheckDeadline(started, timeout, cancellationToken); requireEffectAuthorization();
                if (progress.QueuedFrames == 0)
                {
                    if (SubmittedFrames == 0) break; // No Start, time or audible-output claim for an empty source.
                    if (anchor is null)
                    {
                        anchor = progress;
                        // Anchor AFTER both native calls return, never before a delayed read.
                        anchorHost = _time.GetTimestamp();
                        if (ReportedLatency100Nanoseconds >= CheckDeadline(started, timeout, cancellationToken).Ticks)
                            throw new TimeoutException("The remaining completion budget cannot satisfy the full reported output latency.");
                    }
                    else
                    {
                        var elapsed = _time.GetElapsedTime(anchorHost);
                        if (elapsed < TimeSpan.Zero) throw new IOException("The output tail clock moved backwards.");
                        ulong advance = progress.DevicePosition - anchor.Value.DevicePosition;
                        if (elapsed.Ticks >= ReportedLatency100Nanoseconds && advance > 0 &&
                            (UInt128)advance * TimeSpan.TicksPerSecond >= (UInt128)ReportedLatency100Nanoseconds * progress.DeviceFrequency)
                        {
                            tail = new(ReportedLatency100Nanoseconds, anchor.Value.DevicePosition,
                                progress.DevicePosition, progress.DeviceFrequency, elapsed);
                            break;
                        }
                    }
                }
                WaitNext(started, timeout, cancellationToken);
            }
            // A changed latency contradicts the same-client lifetime contract; do not
            // silently substitute a newly reported bound after waiting the old one.
            RequireSOk(_client.GetStreamLatency(out long finalLatency), "recheck output stream latency");
            if (finalLatency != ReportedLatency100Nanoseconds)
                throw new InvalidDataException("The selected output changed its reported stream latency.");
            CheckDeadline(started, timeout, cancellationToken); requireEffectAuthorization();
            Dispose();
            CheckDeadline(started, timeout, cancellationToken); requireEffectAuthorization();
            CheckDeadline(started, timeout, cancellationToken);
            State = ExclusivePcmOutputState.Completed;
            return new(SubmittedFrames, tail);
        }
        catch (Exception failure) { Fail(failure); throw; }
    }

    private ExclusivePcmProgress ReadProgress()
    {
        var queued = ReadQueuedFrames(); var clock = ReadClock();
        return new(SubmittedFrames, _retiredFrames, queued, clock.Position, clock.Frequency);
    }
    private uint ReadQueuedFrames()
    {
        var queued = _client.GetQueuedFrames();
        if (queued > BufferFrames || queued > SubmittedFrames || SubmittedFrames - queued < _retiredFrames)
            throw new InvalidDataException("The native endpoint returned inconsistent queue accounting.");
        _retiredFrames = SubmittedFrames - queued;
        return queued;
    }
    private (ulong Position, ulong Frequency) ReadClock()
    {
        for (int attempt = 0; attempt < MaximumClockReadAttempts; attempt++)
        {
            var result = _client.GetClockPosition(out var position, out var frequency);
            if (result == 1) continue; // S_FALSE is explicitly imprecise; its values are never published.
            RequireSOk(result, "read an accurate output device clock");
            if (frequency == 0 || (_hasClock && (frequency != _clockFrequency || position < _lastClockPosition)))
                throw new InvalidDataException("The output device clock changed frequency or moved backwards.");
            _hasClock = true; _clockFrequency = frequency; _lastClockPosition = position;
            return (position, frequency);
        }
        throw new IOException("The output device clock remained imprecise after three reads.");
    }
    private static void ValidateTimeout(TimeSpan timeout)
    { if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(5)) throw new ArgumentOutOfRangeException(nameof(timeout)); }
    private TimeSpan CheckDeadline(long started, TimeSpan timeout, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); var elapsed = _time.GetElapsedTime(started);
        if (elapsed < TimeSpan.Zero) throw new IOException("The output deadline clock moved backwards.");
        if (elapsed >= timeout) throw new TimeoutException("The selected output endpoint exceeded its progress deadline.");
        return timeout - elapsed;
    }
    private void WaitNext(long started, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var remaining = CheckDeadline(started, timeout, cancellationToken);
        _client.WaitForProgress(remaining < _pollInterval ? remaining : _pollInterval, cancellationToken);
    }

    // Immediate stop never produces an endpoint-drain or playback-completion receipt.
    public void Stop()
    {
        RequireThread(); if (CleanupFailure is not null) throw CleanupFailure;
        if (_disposed || State is ExclusivePcmOutputState.Stopped or ExclusivePcmOutputState.Disposed) return;
        try
        {
            if (_startAttempted) _client.Stop();
            _startAttempted = false;
            if (State != ExclusivePcmOutputState.Faulted) State = ExclusivePcmOutputState.Stopped;
        }
        catch { State = ExclusivePcmOutputState.Faulted; throw; }
    }

    public void Dispose()
    {
        RequireThread();
        if (_disposed) { if (CleanupFailure is not null) throw CleanupFailure; return; }
        _disposed = true; var errors = new List<Exception>();
        if (_startAttempted) Attempt(_client.Stop, errors);
        Attempt(_client.Dispose, errors); Attempt(_device.Dispose, errors);
        if (errors.Count != 0)
        {
            State = ExclusivePcmOutputState.CleanupFailed;
            CleanupFailure = new AggregateException("Output cleanup failed; release is unconfirmed.", errors); throw CleanupFailure;
        }
        _startAttempted = false; State = ExclusivePcmOutputState.Disposed;
    }
    private void Fail(Exception failure)
    {
        try { Dispose(); }
        catch (Exception cleanup) { throw new AggregateException("Output failed and release is unconfirmed.", failure, cleanup); }
        State = ExclusivePcmOutputState.Faulted;
    }
    private void RequireThread()
    { if (Environment.CurrentManagedThreadId != _threadId) throw new InvalidOperationException("Use and release output on its owning worker thread."); }
    private void RequireOpenThread() { RequireThread(); ObjectDisposedException.ThrowIf(_disposed, this); }
    internal static long PeriodForFrames(ExactPcmFormat format, uint frames)
    {
        CheckedBufferBytes(format, frames);
        var period = checked(((long)frames * 10_000_000 + format.SampleRate / 2) / format.SampleRate);
        if (period == 0) throw new InvalidDataException("Output period is below the native clock resolution.");
        return period;
    }
    private static int CheckedBufferBytes(ExactPcmFormat format, uint frames)
    {
        if (frames == 0 || frames > format.SampleRate) throw new InvalidDataException("The native output buffer must be positive and at most one second.");
        var bytes = checked((long)frames * format.BytesPerFrame);
        if (bytes > MaximumPeriodBytes) throw new InvalidDataException("The native output buffer exceeds the memory limit.");
        return (int)bytes;
    }
    internal static void RequireSOk(int result, string operation)
    { if (result != 0) throw new IOException($"Unable to {operation} (HRESULT 0x{result:X8})."); }
    // IAudioClient::Stop explicitly returns S_FALSE when already stopped, including after
    // a Start failure. This exception does not apply to format acceptance or clock precision.
    internal static void RequireStopped(int result)
    { if (result is not (0 or 1)) throw new IOException($"Unable to stop exclusive output (HRESULT 0x{result:X8})."); }
    internal static void RequireSuccess(int result, string operation)
    { if (result < 0) throw new IOException($"Unable to {operation} (HRESULT 0x{result:X8})."); }
    internal static void Attempt(Action cleanup, ICollection<Exception> errors)
    { try { cleanup(); } catch (Exception error) { errors.Add(error); } }
}
