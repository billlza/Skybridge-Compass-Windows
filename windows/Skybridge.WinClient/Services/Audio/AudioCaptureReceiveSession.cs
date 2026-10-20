using System.Buffers.Binary;
using System.Runtime.ExceptionServices;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioCaptureReceivePhase { Idle, AwaitingOffer, Authorizing, SelectingOutput, AwaitingApproval, ReceivingFile, Preparing, Buffering, Playing, Finishing, Stopping, Completed, Failed }
internal abstract record AudioPlaybackReceiveReceipt(Guid StreamId, AudioStreamingPcmFormat Format, ExclusivePcmPlaybackReceipt Output)
{
    internal sealed record Captured(Guid StreamId, AudioStreamingPcmFormat Format, AudioCaptureContentReceipt Content,
        ExclusivePcmPlaybackReceipt Output) : AudioPlaybackReceiveReceipt(StreamId, Format, Output);
    internal sealed record OriginalFile(Guid StreamId, AudioStreamingPcmFormat Format, long FileBytes, string FileSha256Hex,
        ExclusivePcmPlaybackReceipt Output) : AudioPlaybackReceiveReceipt(StreamId, Format, Output);
}
internal sealed class AudioCaptureReceiveException(AudioStreamingStopReason reason, Exception cause,
    IReadOnlyList<Exception> cleanupFailures, bool nativeReleaseConfirmed, bool fileReleaseConfirmed = true)
    : IOException($"Audio reception failed: {reason}.", cleanupFailures.Count == 0 ? cause : new AggregateException(new[] { cause }.Concat(cleanupFailures)))
{
    internal AudioStreamingStopReason Reason { get; } = reason;
    internal Exception Cause { get; } = cause;
    internal IReadOnlyList<Exception> CleanupFailures { get; } = cleanupFailures;
    internal bool NativeReleaseConfirmed { get; } = nativeReleaseConfirmed;
    internal bool FileReleaseConfirmed { get; } = fileReleaseConfirmed;
}

/// <summary>One captured-PCM or original-file receiver. A dedicated thread owns every native call,
/// hash/counter update and cleanup. The existing MAIN reader supplies one pending
/// inbox read; no additional PCM queue or transport reader is created. UI/account
/// adapters remain asynchronous before rendering, and the bounded control writer
/// owns network writes while this thread renders.</summary>
internal sealed class AudioCaptureReceiveSession : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly LanProductControlSession _session;
    private readonly Func<ILanAudioStreamInbox, CancellationToken, Task<AccountAudioMembershipLease>> _authorize;
    private readonly Func<ILanAudioStreamInbox, AccountAudioMembershipLease, CancellationToken, Task<AccountAudioMembershipLease>>? _renewMembership;
    private readonly Func<AudioAuthorizationTime>? _membershipClock;
    private readonly Func<TimeSpan, CancellationToken, Task>? _renewalDelay;
    private AudioMembershipRenewal? _renewal;
    private Task? _renewalTask;
    private readonly Func<CancellationToken, Task<string>> _selectOutput;
    private readonly AudioPlaybackApprovalService _approvals;
    private readonly Func<string, IExclusivePcmDevice> _openDevice;
    private readonly TimeProvider _time;
    private readonly AudioOriginalFileReceiveRegistry? _originalFiles;
    private AudioOriginalFileReceiveRegistry.Ticket? _fileTicket;
    private Task<AudioPreparedOriginalFile>? _fileInspection;
    // Android starts one 120-second deadline after sending the offer. Leave ten
    // seconds for transport/peer scheduling; local phases never reset this budget.
    private static readonly TimeSpan AdmissionBudget = TimeSpan.FromSeconds(110);
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<AudioPlaybackReceiveReceipt> _body = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _offerReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task<AudioPlaybackReceiveReceipt>? _run;
    private CancellationTokenSource? _scope;
    private Thread? _thread;
    private bool _threadStarted, _closed;
    private int _phase;
    // Retained on failure, including uncertain native cleanup. A host must not drop
    // this owner or start a replacement output when NativeReleaseConfirmed is false.
    private ExclusivePcmOutput? _output;
    private Exception? _failure;
    private Exception? _disposeFailure;
    private bool _nativeReleaseConfirmed = true;
    private ILanAudioStreamInbox? _inbox;
    private ILanAudioStreamInbox? _acceptedInbox;
    private AudioPlaybackPermission? _permission;
    private AudioCaptureReceiveFlow? _flow;
    private AudioReceiverControlWriter? _writer;
    private Task<AudioStreamingMessage>? _read;
    private Task? _admission;
    private Task? _creditDelivery;
    private bool _peerEnded, _playing;
    private string? _endpoint;
    private long _lastCredit;
    private long _admissionStarted;
    private int _admissionPending;

    internal AudioCaptureReceiveSession(LanProductControlSession session,
        Func<ILanAudioStreamInbox, CancellationToken, Task<AccountAudioMembershipLease>> authorize,
        Func<ILanAudioStreamInbox, AccountAudioMembershipLease, CancellationToken, Task<AccountAudioMembershipLease>>? renewMembership,
        Func<CancellationToken, Task<string>> selectOutput, AudioPlaybackApprovalService approvals,
        Func<string, IExclusivePcmDevice>? openDevice = null, TimeProvider? time = null,
        AudioOriginalFileReceiveRegistry? originalFiles = null, Func<AudioAuthorizationTime>? membershipClock = null,
        Func<TimeSpan, CancellationToken, Task>? renewalDelay = null)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _authorize = authorize ?? throw new ArgumentNullException(nameof(authorize));
        _renewMembership = renewMembership; _membershipClock = membershipClock; _renewalDelay = renewalDelay;
        _selectOutput = selectOutput ?? throw new ArgumentNullException(nameof(selectOutput));
        _approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        _openDevice = openDevice ?? OpenNative;
        _time = time ?? TimeProvider.System;
        _originalFiles = originalFiles;
    }
    internal AudioCaptureReceivePhase Phase => (AudioCaptureReceivePhase)Volatile.Read(ref _phase);
    internal bool NativeReleaseConfirmed => Volatile.Read(ref _nativeReleaseConfirmed);
    internal bool FileReleaseConfirmed => _fileTicket is null || _fileTicket.ReleaseConfirmed;
    internal bool ResourcesReleaseConfirmed => NativeReleaseConfirmed && FileReleaseConfirmed;
    internal Exception? Failure => Volatile.Read(ref _failure);
    internal AudioMembershipRenewalSnapshot? RenewalSnapshot => Volatile.Read(ref _renewal)?.Snapshot;
    // The host must install the actual offer waiter before advertising/using the consumer.
    internal Task ReadyForOffer => _offerReady.Task;
    private static IExclusivePcmDevice OpenNative(string endpoint)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native capture reception requires Windows.");
        return WindowsExclusivePcmDevice.Open(endpoint);
    }

    internal Task<AudioPlaybackReceiveReceipt> RunAsync(CancellationToken cancellationToken) => Start(null, cancellationToken);
    // A product listener can await offers asynchronously, then transfer its exact
    // inbox to the native worker. No native thread is needed for an idle device.
    internal Task<AudioPlaybackReceiveReceipt> RunAcceptedAsync(ILanAudioStreamInbox inbox, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        return Start(inbox, cancellationToken);
    }
    private Task<AudioPlaybackReceiveReceipt> Start(ILanAudioStreamInbox? accepted, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_run is not null) throw new InvalidOperationException("Captured audio reception is single-use.");
            if (accepted is not null) _session.RequireOwnedAudioInbox(accepted);
            _acceptedInbox = accepted;
            _scope = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _session.Lifetime, _stop.Token);
            _thread = new Thread(Execute) { IsBackground = true, Name = "SkyBridge audio output" };
            _run = JoinAfterBodyAsync(_thread);
            try { _thread.Start(); _threadStarted = true; }
            catch (Exception error)
            {
                if (accepted is not null)
                {
                    try { accepted.Dispose(); }
                    catch (Exception cleanup) { error = new AggregateException(error, cleanup); }
                }
                _scope.Dispose(); Volatile.Write(ref _failure, error); PhaseIs(AudioCaptureReceivePhase.Failed);
                _offerReady.TrySetException(error); _body.TrySetException(error);
            }
            return _run;
        }
    }
    private async Task<AudioPlaybackReceiveReceipt> JoinAfterBodyAsync(Thread thread)
    {
        try { return await _body.Task.ConfigureAwait(false); }
        finally
        {
            bool started; lock (_gate) started = _threadStarted;
            if (started) await Task.Run(thread.Join).ConfigureAwait(false);
        }
    }
    private CancellationToken Token => (_scope ?? throw new InvalidOperationException("Receiver scope has not started.")).Token;
    private void PhaseIs(AudioCaptureReceivePhase phase) => Volatile.Write(ref _phase, (int)phase);

    private void Execute()
    {
        AudioPlaybackReceiveReceipt? receipt = null;
        Exception? primary = null; var reason = AudioStreamingStopReason.OutputLost;
        var cleanup = new List<Exception>();
        try { receipt = Receive(); }
        catch (Exception error) { primary = error; reason = Reason(error); _offerReady.TrySetException(error); }
        finally
        {
            PhaseIs(AudioCaptureReceivePhase.Stopping);
            _permission?.Revoke();
            Try(() => _scope!.Cancel());
            // Await actual adapters/readers even if they ignore cancellation. No new
            // stream or cleanup-success receipt can escape while they are still live.
            if (_admission is { } admission)
            {
                Try(() => admission.GetAwaiter().GetResult(), expectedCancellation: true);
                if (admission is Task<AudioPlaybackPermission> approval && approval.IsCompletedSuccessfully) approval.Result.Revoke();
            }
            if (_read is { } read) Try(() => read.GetAwaiter().GetResult(), expectedCancellation: true);
            if (_fileInspection is { } inspection) Try(() => inspection.GetAwaiter().GetResult(), expectedCancellation: true);
            if (_writer is { } writer) Try(() => writer.DisposeAsync().AsTask().GetAwaiter().GetResult());
            if (_flow is { } flow) Try(flow.Dispose);
            if (_output is { } output)
            {
                Try(output.Dispose);
                Volatile.Write(ref _nativeReleaseConfirmed, output.CleanupFailure is null);
            }
            bool uncertainOpen = Contains<ExclusivePcmOpenCleanupException>(primary) || cleanup.Any(Contains<ExclusivePcmOpenCleanupException>);
            Volatile.Write(ref _nativeReleaseConfirmed, !uncertainOpen && (_output is null || _output.CleanupFailure is null));
            if (_fileTicket is { } ticket) Try(() => ticket.CloseAsync().GetAwaiter().GetResult());
            if (primary is not null && _inbox is { } inbox && !_peerEnded)
                Try(() => _session.SendAudioStopAsync(inbox, reason, CancellationToken.None).GetAwaiter().GetResult());
            if (_inbox is { } ownedInbox) Try(ownedInbox.Dispose);
            // Native/file/carrier effects have ended before joining account I/O.
            // A request ignoring cancellation still belongs to this receive session.
            if (_renewalTask is { } renewal) Try(() => renewal.GetAwaiter().GetResult(), expectedCancellation: true);
            _scope!.Dispose();
        }
        if (primary is null && cleanup.Count == 0 && receipt is not null && ResourcesReleaseConfirmed)
        {
            PhaseIs(AudioCaptureReceivePhase.Completed); _body.TrySetResult(receipt);
        }
        else
        {
            primary ??= new IOException("Captured audio cleanup did not complete successfully.");
            var failure = new AudioCaptureReceiveException(reason, primary, cleanup.AsReadOnly(), NativeReleaseConfirmed, FileReleaseConfirmed);
            Volatile.Write(ref _failure, failure); PhaseIs(AudioCaptureReceivePhase.Failed); _body.TrySetException(failure);
        }
        void Try(Action action, bool expectedCancellation = false)
        {
            try { action(); }
            catch (OperationCanceledException error) when (expectedCancellation && error.InnerException is null &&
                error.CancellationToken == Token && Token.IsCancellationRequested) { }
            catch (Exception error)
            {
                if (!Includes(primary, error) && !cleanup.Any(existing => Includes(existing, error))) cleanup.Add(error);
            }
        }
    }

    private AudioPlaybackReceiveReceipt Receive()
    {
        PhaseIs(AudioCaptureReceivePhase.AwaitingOffer);
        if (_acceptedInbox is { } accepted)
        {
            _inbox = accepted; _offerReady.TrySetResult();
            _session.RequireOwnedAudioInbox(accepted);
        }
        else
        {
            var accepting = _session.AcceptAudioOfferAsync(Token);
            _offerReady.TrySetResult();
            _inbox = accepting.GetAwaiter().GetResult();
        }
        var offer = _inbox.ReadAsync(Token).GetAwaiter().GetResult();
        _admissionStarted = _time.GetTimestamp();
        Volatile.Write(ref _admissionPending, 1);
        var source = _inbox.Source;
        if (AudioPlaybackSource.FromOffer(offer) != source ||
            source is AudioPlaybackSource.OriginalFile && _originalFiles?.CanReceiveFor(_session) != true)
            throw new StreamFailure(AudioStreamingStopReason.UnsupportedSource, "The exact source receiver is unavailable.");
        if (source is AudioPlaybackSource.CapturedPcm captured && captured.Format.BytesPerFrame > AudioStreamingWire.MaximumPcmDataBytes)
            throw new StreamFailure(AudioStreamingStopReason.UnsupportedSource, "One source frame exceeds the transport packet limit.");
        _read = _inbox.ReadAsync(Token);
        PhaseIs(AudioCaptureReceivePhase.Authorizing);
        var membership = AwaitAdmission(_authorize(_inbox, Token), TimeSpan.FromSeconds(45));
        membership.RequireInbox(_inbox); membership.RequireCurrent();
        PhaseIs(AudioCaptureReceivePhase.SelectingOutput);
        _endpoint = AwaitAdmission(_selectOutput(Token), TimeSpan.FromSeconds(5));
        PhaseIs(AudioCaptureReceivePhase.AwaitingApproval);
        _permission = AwaitAdmission(_approvals.RequestAsync(_inbox, membership, _endpoint, Token), TimeSpan.FromSeconds(65));
        if (source is AudioPlaybackSource.OriginalFile original) return ReceiveFile(original, membership);
        StartRenewal(membership);
        var format = source is AudioPlaybackSource.CapturedPcm capturedSource ? capturedSource.Format
            : throw new StreamFailure(AudioStreamingStopReason.UnsupportedSource, "Unsupported audio source type.");
        PhaseIs(AudioCaptureReceivePhase.Preparing); RequireEffect(); RejectPrematureInput();
        long preparation = _time.GetTimestamp();
        var exact = format.RequireExactOutputFormat();
        uint requested = (uint)Math.Min(((ulong)format.SampleRate + 4) / 5, (ulong)ExclusivePcmOutput.MaximumPeriodBytes / format.BytesPerFrame);
        Volatile.Write(ref _nativeReleaseConfirmed, false);
        _output = ExclusivePcmOutput.Open(_openDevice(_endpoint), exact, Math.Max(1, requested), _time);
        Deadline(preparation, TimeSpan.FromSeconds(10)); RequireControlDeadline(); RequireEffect(); RejectPrematureInput();
        int frameBytes = checked((int)format.BytesPerFrame);
        long limit = Math.Min(AudioStreamingWire.MaximumReceiveWindowBytes,
            Math.Min(6L * AudioStreamingWire.MaximumPcmDataBytes, 2L * _output.BufferBytes));
        uint window = checked((uint)(limit - limit % frameBytes));
        _flow = new(_inbox.StreamId, format, window);
        ulong prefill = Math.Min(_output.BufferFrames, Math.Min(window / format.BytesPerFrame, Math.Max(1U, format.SampleRate / 10)));
        _writer = new(_session, _inbox, _permission, Token, RequireControlDeadline);
        AwaitAdmissionControl(_writer.Queue(new AudioStreamingBody.Accept(window)));
        RejectPrematureInput();
        AwaitAdmissionControl(_writer.Queue(new AudioStreamingBody.OutputReady(format)));
        Volatile.Write(ref _admissionPending, 0);
        PhaseIs(AudioCaptureReceivePhase.Buffering);
        while (true)
        {
            RequireEffect(); uint queued = ObserveCredit();
            if (_read!.IsCompleted)
            {
                var message = TakeRead();
                switch (message.Body)
                {
                    case AudioStreamingBody.PcmData:
                        _flow.Enqueue(message, bytes => { RequireFinite(bytes, format); SubmitPacket(bytes); });
                        if (!_playing && _output.SubmittedFrames >= prefill) StartOutput();
                        _read = _inbox.ReadAsync(Token);
                        break;
                    case AudioStreamingBody.End:
                        AudioCaptureContentReceipt content;
                        try { content = _flow.VerifyEnd(message); }
                        catch (InvalidDataException error) { throw new StreamFailure(AudioStreamingStopReason.ContentMismatch, "Captured content failed final verification.", error); }
                        _writer.Queue(new AudioStreamingBody.ContentVerified(content.TotalBytes, Convert.FromHexString(content.Sha256Hex)));
                        PhaseIs(AudioCaptureReceivePhase.Finishing);
                        _output.FinishInput(checked((ulong)content.SourceFrames));
                        if (!_playing && content.SourceFrames > 0) StartOutput();
                        var rendered = _output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(5), Token, RequireEffect);
                        if (rendered.SourceFrames != (ulong)content.SourceFrames)
                            throw new StreamFailure(AudioStreamingStopReason.OutputLost, "Output extent differs from the verified source.");
                        _flow.Retire(content.SourceFrames); SendCredit(force: true);
                        _flow.Dispose(); _flow = null;
                        RequireEffect();
                        _writer.Queue(new AudioStreamingBody.PlaybackComplete(content.SourceFrames, 0)).GetAwaiter().GetResult();
                        _writer.DrainAsync().GetAwaiter().GetResult();
                        return new AudioPlaybackReceiveReceipt.Captured(_inbox.StreamId, format, content, rendered);
                    default: throw new StreamFailure(AudioStreamingStopReason.ProtocolViolation, "Unexpected captured audio input.");
                }
            }
            else
            {
                if (_playing && queued > 0) _output.Pace(Token);
                // Capture WouldBlock is not EOF. With no running source queue,
                // wait for the one existing read and recheck finite authorization.
                // New PCM after actual exhaustion still fails in SubmitPacket.
                else Task.WhenAny(_read, Task.Delay(TimeSpan.FromMilliseconds(25), Token)).GetAwaiter().GetResult();
            }
        }
    }

    private AudioPlaybackReceiveReceipt ReceiveFile(AudioPlaybackSource.OriginalFile source, AccountAudioMembershipLease membership)
    {
        RequireEffect(); RejectPrematureInput();
        _fileTicket = (_originalFiles ?? throw new InvalidOperationException("No file receiver is installed.")).Register(
            new AudioOriginalFileAdmission(_session, _inbox!, _permission!, _endpoint!));
        StartRenewal(membership);
        _writer = new(_session, _inbox!, _permission!, Token, RequireControlDeadline);
        AwaitAdmissionControl(_writer.Queue(new AudioStreamingBody.Accept(0)));
        Volatile.Write(ref _admissionPending, 0);
        PhaseIs(AudioCaptureReceivePhase.ReceivingFile);
        var waiting = _fileTicket.WaitForArtifactAsync();
        long start = _time.GetTimestamp();
        while (!waiting.IsCompleted)
        {
            RequireFileEffect(); _fileTicket.RequireCurrent();
            Deadline(start, _fileTicket.HasStarted ? TimeSpan.FromMinutes(6) : TimeSpan.FromSeconds(60));
            Task.WhenAny(waiting, _read!, Task.Delay(25, Token)).GetAwaiter().GetResult();
        }
        var artifact = waiting.GetAwaiter().GetResult(); RequireFileEffect();
        PhaseIs(AudioCaptureReceivePhase.Preparing);
        long preparing = _time.GetTimestamp();
        _fileInspection = AudioPreparedOriginalFile.PrepareAsync(artifact, RequireFileEffect, Token, _time);
        while (!_fileInspection.IsCompleted)
        {
            RequireFileEffect(); Deadline(preparing, AudioPreparedOriginalFile.MaximumPreparationTime);
            Task.WhenAny(_fileInspection, _read!, Task.Delay(25, Token)).GetAwaiter().GetResult();
        }
        var prepared = _fileInspection.GetAwaiter().GetResult();
        RequireFileEffect(); Deadline(preparing, AudioPreparedOriginalFile.MaximumPreparationTime);
        var format = prepared.Format;
        var exact = format.RequireExactOutputFormat();
        preparing = _time.GetTimestamp();
        uint requested = (uint)Math.Min(((ulong)format.SampleRate + 4) / 5, (ulong)ExclusivePcmOutput.MaximumPeriodBytes / format.BytesPerFrame);
        Volatile.Write(ref _nativeReleaseConfirmed, false);
        _output = ExclusivePcmOutput.Open(_openDevice(_endpoint!), exact, Math.Max(1, requested), _time);
        RequireFileEffect(); Deadline(preparing, TimeSpan.FromSeconds(10));
        _writer.Queue(new AudioStreamingBody.OutputReady(format)).GetAwaiter().GetResult();
        PhaseIs(AudioCaptureReceivePhase.Buffering);
        var rendered = prepared.Play(_output, RequireFileEffect, Token, _time,
            () => PhaseIs(AudioCaptureReceivePhase.Playing));
        RequireFileEffect(); PhaseIs(AudioCaptureReceivePhase.Finishing);
        if (rendered.SourceFrames != (ulong)prepared.FrameCount)
            throw new StreamFailure(AudioStreamingStopReason.OutputLost, "File output extent differs from its declared source.");
        _fileTicket.CloseAsync().GetAwaiter().GetResult(); RequireFileEffect();
        if (!FileReleaseConfirmed) throw new IOException("Private file release is unconfirmed.");
        _writer.Queue(new AudioStreamingBody.PlaybackComplete(prepared.FrameCount, 0)).GetAwaiter().GetResult();
        _writer.DrainAsync().GetAwaiter().GetResult();
        return new AudioPlaybackReceiveReceipt.OriginalFile(_inbox!.StreamId, format, source.Length, source.Sha256Hex, rendered);
    }
    private void RequireFileEffect()
    {
        RequireEffect();
        if (_read is { IsCompleted: true })
        {
            var message = TakeRead(); // Preserve an actual Stop/owner failure.
            if (Phase == AudioCaptureReceivePhase.ReceivingFile &&
                _fileTicket is { UsesUsbReturn: true, HasStarted: false } ticket &&
                message.Body is AudioStreamingBody.UsbFileRoute route)
            {
                _read = _inbox!.ReadAsync(Token);
                ticket.StartUsbReturn(route.Port, Token);
                return;
            }
            throw new StreamFailure(AudioStreamingStopReason.ProtocolViolation, "Original-file playback does not accept capture controls.");
        }
    }

    private T AwaitAdmission<T>(Task<T> task, TimeSpan timeout)
    {
        _admission = task;
        Task.WhenAny(task, _read!).WaitAsync(RemainingAdmission(timeout), Token).GetAwaiter().GetResult();
        RejectPrematureInput();
        var result = task.GetAwaiter().GetResult();
        RequireControlDeadline(); _inbox!.RequireCurrent(); _admission = null;
        return result;
    }
    private TimeSpan RemainingAdmission(TimeSpan phaseBudget)
    {
        Token.ThrowIfCancellationRequested();
        var elapsed = _time.GetElapsedTime(_admissionStarted);
        if (elapsed < TimeSpan.Zero || elapsed >= AdmissionBudget)
            throw new TimeoutException("Captured audio admission exceeded its total deadline.");
        return TimeSpan.FromTicks(Math.Min(phaseBudget.Ticks, (AdmissionBudget - elapsed).Ticks));
    }
    private void RequireControlDeadline()
    {
        if (Volatile.Read(ref _admissionPending) != 0) Deadline(_admissionStarted, AdmissionBudget);
    }
    private void AwaitAdmissionControl(Task delivery)
    {
        delivery.WaitAsync(RemainingAdmission(AdmissionBudget), Token).GetAwaiter().GetResult();
        RequireControlDeadline();
    }
    private void RejectPrematureInput()
    {
        if (_read?.IsCompleted != true) return;
        _ = TakeRead(); // A terminal inbox failure retains its actual Stop/owner cause.
        throw new StreamFailure(AudioStreamingStopReason.ProtocolViolation, "Audio input arrived before output readiness.");
    }
    private AudioStreamingMessage TakeRead()
    {
        var read = _read ?? throw new InvalidOperationException("No pending input read."); _read = null;
        return read.GetAwaiter().GetResult();
    }
    private void StartOutput()
    {
        RequireEffect(); _output!.Start(); _playing = true;
        if (Phase != AudioCaptureReceivePhase.Finishing) PhaseIs(AudioCaptureReceivePhase.Playing);
    }
    private void SubmitPacket(byte[] bytes)
    {
        var output = _output ?? throw new InvalidOperationException("No prepared output.");
        long started = _time.GetTimestamp(); int offset = 0;
        while (offset < bytes.Length)
        {
            RequireEffect(); Deadline(started, TimeSpan.FromSeconds(5));
            var progress = output.ObserveProgress();
            if (_playing && progress.QueuedFrames == 0)
                throw new StreamFailure(AudioStreamingStopReason.OutputLost, "The output endpoint exhausted before additional source frames could be submitted.");
            uint available = output.BufferFrames - progress.QueuedFrames;
            if (available == 0)
            {
                if (!_playing) StartOutput();
                output.Pace(Token); continue;
            }
            int count = checked((int)Math.Min((long)available * output.Format.BytesPerFrame, bytes.Length - offset));
            RequireEffect(); output.Submit(bytes, offset, count, requireQueuedFrames: _playing); offset += count;
        }
    }
    private uint ObserveCredit()
    {
        var flow = _flow ?? throw new InvalidOperationException("No capture accounting.");
        var progress = _output!.ObserveProgress();
        if (progress.SubmittedSourceFrames != (ulong)(flow.ReceivedBytes / flow.Format.BytesPerFrame))
            throw new StreamFailure(AudioStreamingStopReason.OutputLost, "Native acceptance differs from captured accounting.");
        flow.Retire(checked((long)progress.RetiredSourceFrames)); SendCredit(force: false);
        return progress.QueuedFrames;
    }
    private void SendCredit(bool force)
    {
        var flow = _flow ?? throw new InvalidOperationException("No capture accounting.");
        long threshold = Math.Max(flow.Format.BytesPerFrame, flow.WindowBytes / 4);
        if (flow.RetiredBytes > _lastCredit && (force || flow.RetiredBytes - _lastCredit >= threshold))
        {
            _creditDelivery = _writer!.Queue(new AudioStreamingBody.Credit(flow.RetiredBytes));
            _lastCredit = flow.RetiredBytes;
        }
    }
    private void StartRenewal(AccountAudioMembershipLease membership)
    {
        if (_renewMembership is not { } renew) return; // Explicit offline/test configuration; no account request.
        var inbox = _inbox ?? throw new InvalidOperationException("No renewal stream owner.");
        membership.RequireInbox(inbox); membership.RequireCurrent();
        var renewal = new AudioMembershipRenewal(membership, token => renew(inbox, membership, token), _membershipClock, _renewalDelay);
        Volatile.Write(ref _renewal, renewal);
        _renewalTask = Task.Run(() => renewal.RunAsync(Token));
    }
    private void RequireEffect()
    {
        Token.ThrowIfCancellationRequested();
        if (RenewalSnapshot is { State: AudioMembershipRenewalState.Failed, Failure: { } failure })
            throw new StreamFailure(AudioStreamingStopReason.AccountRevoked, "Account renewal ended this playback authorization.", failure);
        if (_writer?.Completion.IsCompleted == true) _writer.Completion.GetAwaiter().GetResult();
        if (_creditDelivery?.IsCompleted == true) _creditDelivery.GetAwaiter().GetResult();
        var inbox = _inbox ?? throw new InvalidOperationException("No captured stream owner.");
        try { (_permission ?? throw new InvalidOperationException("No playback approval.")).RequireEffectCurrent(inbox, inbox.Source, _endpoint!); }
        catch (LanAudioStreamException) { _peerEnded = true; throw; }
        catch (InvalidOperationException error) { throw new StreamFailure(AudioStreamingStopReason.AccountRevoked, "The account authorization ended.", error); }
        Token.ThrowIfCancellationRequested();
    }
    private void Deadline(long started, TimeSpan timeout)
    {
        Token.ThrowIfCancellationRequested(); var elapsed = _time.GetElapsedTime(started);
        if (elapsed < TimeSpan.Zero || elapsed >= timeout) throw new TimeoutException("Captured audio reception exceeded its progress deadline.");
    }
    private static void RequireFinite(ReadOnlySpan<byte> bytes, AudioStreamingPcmFormat format)
    {
        if (!format.FloatingPoint) return;
        int size = format.ContainerBits / 8;
        for (int offset = 0; offset < bytes.Length; offset += size)
        {
            bool finite = size == 4
                ? (BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]) & 0x7f800000U) != 0x7f800000U
                : (BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]) & 0x7ff0000000000000UL) != 0x7ff0000000000000UL;
            if (!finite) throw new StreamFailure(AudioStreamingStopReason.UnsupportedSource, "Captured PCM contains a non-finite sample.");
        }
    }
    private AudioStreamingStopReason Reason(Exception error)
    {
        if (error is LanAudioStreamException stream) { _peerEnded = true; return stream.Reason; }
        if (error is StreamFailure failure) return failure.Reason;
        if (error is AudioFilePcmPlaybackException file) return file.Reason;
        if (error is OperationCanceledException) return AudioStreamingStopReason.UserStopped;
        if (error is TimeoutException) return AudioStreamingStopReason.TimedOut;
        if (error is AudioWavePcmFileException or AudioFlacMetadataException or AudioFlacDecodeException or AudioOriginalFilePreparationException or AudioFlacComponentException)
            return AudioStreamingStopReason.UnsupportedSource;
        if (error is AudioMembershipException) return AudioStreamingStopReason.AccountRevoked;
        if (error is AudioPlaybackApprovalException approval)
            return approval.Reason switch
            {
                AudioPlaybackApprovalFailure.TimedOut => AudioStreamingStopReason.TimedOut,
                AudioPlaybackApprovalFailure.Revoked or AudioPlaybackApprovalFailure.ClockChanged => AudioStreamingStopReason.PermissionRevoked,
                _ => AudioStreamingStopReason.ReceiverDeclined
            };
        return Phase switch
        {
            AudioCaptureReceivePhase.Authorizing => AudioStreamingStopReason.AccountRevoked,
            AudioCaptureReceivePhase.SelectingOutput => AudioStreamingStopReason.UnsupportedOutput,
            AudioCaptureReceivePhase.AwaitingApproval => AudioStreamingStopReason.ReceiverDeclined,
            AudioCaptureReceivePhase.Preparing => AudioStreamingStopReason.UnsupportedOutput,
            _ when error is InvalidDataException => AudioStreamingStopReason.ProtocolViolation,
            _ => AudioStreamingStopReason.OutputLost
        };
    }
    private static bool Contains<T>(Exception? error) where T : Exception => error is T ||
        error is AggregateException aggregate && aggregate.InnerExceptions.Any(Contains<T>) || error?.InnerException is { } inner && Contains<T>(inner);
    private static bool Includes(Exception? parent, Exception child) => ReferenceEquals(parent, child) ||
        parent is AggregateException aggregate && aggregate.InnerExceptions.Any(error => Includes(error, child)) ||
        parent?.InnerException is { } inner && Includes(inner, child);
    private sealed class StreamFailure(AudioStreamingStopReason reason, string message, Exception? inner = null) : IOException(message, inner)
    { internal AudioStreamingStopReason Reason { get; } = reason; }

    public async ValueTask DisposeAsync()
    {
        Task<AudioPlaybackReceiveReceipt>? run; bool first;
        lock (_gate) { first = !_closed; _closed = true; run = _run; }
        if (first)
        {
            try { _stop.Cancel(); }
            catch (Exception error) { Volatile.Write(ref _disposeFailure, error); }
        }
        Exception? failure = null;
        try
        {
            if (run is not null) await run.ConfigureAwait(false);
        }
        catch (AudioCaptureReceiveException error) when (error.Reason == AudioStreamingStopReason.UserStopped &&
            error.Cause is OperationCanceledException { InnerException: null } && error.CleanupFailures.Count == 0 && error.NativeReleaseConfirmed && error.FileReleaseConfirmed) { }
        catch (Exception error) { failure = error; }
        finally { if (first) _stop.Dispose(); }
        var disposal = Volatile.Read(ref _disposeFailure);
        if (failure is not null && disposal is not null) throw new AggregateException("Audio receiver and cancellation cleanup failed.", failure, disposal);
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        if (disposal is not null) ExceptionDispatchInfo.Capture(disposal).Throw();
    }
}
