using System.Runtime.ExceptionServices;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>One receiver's bounded positive-control writer, using the existing MAIN
/// sender and its actual admission gate. Four queued controls plus one in flight;
/// absolute credits coalesce without retaining an unbounded list of waiters.
/// The caller retains the inbox and must await disposal before sending a final Stop.</summary>
internal sealed class AudioReceiverControlWriter : IAsyncDisposable
{
    internal const int QueueCapacity = 4;
    private readonly object _gate = new();
    private readonly LanProductControlSession _session;
    private readonly ILanAudioStreamInbox _inbox;
    private readonly AudioPlaybackPermission _permission;
    private readonly Action? _requireSessionEffect;
    private readonly TimeProvider _time;
    private readonly CancellationTokenSource _lifetime;
    private readonly CancellationToken _token;
    private readonly CancellationToken _callerToken;
    private readonly List<Pending> _queue = new(QueueCapacity);
    private readonly Task _run;
    private TaskCompletionSource _changed = Signal();
    private Pending? _sending;
    private bool _sealed, _finished;
    private Exception? _failure;
    private OperationCanceledException? _disposeReason;
    private long _lastRequestedCredit = -1;
    private Task? _lastCreditReceipt;
    private long _latestFileProgress, _sentFileProgress;
    private long? _fileProgressSentAt;

    internal AudioReceiverControlWriter(LanProductControlSession session, ILanAudioStreamInbox inbox,
        AudioPlaybackPermission permission, CancellationToken cancellationToken, Action? requireSessionEffect = null,
        TimeProvider? time = null)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        _permission = permission ?? throw new ArgumentNullException(nameof(permission));
        _requireSessionEffect = requireSessionEffect;
        _time = time ?? TimeProvider.System;
        _callerToken = cancellationToken;
        cancellationToken.ThrowIfCancellationRequested();
        RequireEffect();
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(session.Lifetime, cancellationToken);
        _token = _lifetime.Token;
        _run = RunAsync();
    }
    internal Task Completion => _run;
    internal (int Queued, bool Sending) PendingCount
    { get { lock (_gate) return (_queue.Count, _sending is not null); } }

    // Called by the native owner after a validated observation. A single latest
    // counter coalesces without one task/waiter per sample block. It is advisory:
    // terminal controls supersede it and no delivery promise is returned.
    internal void ObserveFileOutputProgress(long frames)
    {
        if (_inbox.Source is not AudioPlaybackSource.OriginalFile || !_session.CanReportFileOutputProgress)
            throw new InvalidOperationException("File output progress was not negotiated for this stream.");
        RequireEffect(); _token.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_failure is { } failure) ExceptionDispatchInfo.Capture(failure).Throw();
            if (_sealed || _finished) throw new InvalidOperationException("The audio control writer has ended.");
            if (frames < _latestFileProgress) throw new InvalidDataException("Native file progress cannot move backwards.");
            _latestFileProgress = frames;
            if (_sending is null && _queue.Count == 0 && FileProgressDue()) WakeLocked();
        }
    }

    private bool FileProgressDue() => !_sealed && _latestFileProgress > _sentFileProgress &&
        (_fileProgressSentAt is not { } sent || _time.GetElapsedTime(sent) >= TimeSpan.FromSeconds(1));

    // The returned task confirms delivery of this control, or (for coalesced credit)
    // an equal/higher absolute value. It does not mean the entire writer has drained.
    // Metadata is frozen before Queue returns. There is no hidden fire-and-forget send.
    internal Task Queue(AudioStreamingBody body)
    {
        ArgumentNullException.ThrowIfNull(body);
        if (body is not (AudioStreamingBody.Accept or AudioStreamingBody.OutputReady or AudioStreamingBody.Credit or
            AudioStreamingBody.ContentVerified or AudioStreamingBody.PlaybackComplete))
            throw new InvalidDataException("The receiver control writer accepts only positive receiver replies.");
        var frozen = AudioStreamingWire.Decode(AudioStreamingWire.Encode(new(_inbox.StreamId, body))).Body;
        RequireEffect(); _token.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_failure is { } failure) ExceptionDispatchInfo.Capture(failure).Throw();
            if (_sealed || _finished) throw new InvalidOperationException("The audio control writer no longer accepts replies.");
            if (frozen is AudioStreamingBody.Credit credit)
            {
                if (credit.RetiredBytes < _lastRequestedCredit)
                    throw new InvalidDataException("Receiver credit cannot move backwards.");
                if (credit.RetiredBytes == _lastRequestedCredit)
                    return _lastCreditReceipt ?? throw new InvalidOperationException("Missing previously requested credit receipt.");
                var queuedCredit = _queue.LastOrDefault(item => item.Body is AudioStreamingBody.Credit);
                if (queuedCredit is not null)
                {
                    queuedCredit.Body = credit;
                    _lastRequestedCredit = credit.RetiredBytes;
                    _lastCreditReceipt = queuedCredit.Sent.Task;
                    return queuedCredit.Sent.Task;
                }
            }
            if (_queue.Count >= QueueCapacity)
            {
                var overflow = new IOException("The bounded audio receiver control queue overflowed.");
                FailLocked(overflow);
                throw overflow;
            }
            var pending = new Pending(frozen);
            _queue.Add(pending);
            if (frozen is AudioStreamingBody.Credit latest)
            {
                _lastRequestedCredit = latest.RetiredBytes;
                _lastCreditReceipt = pending.Sent.Task;
            }
            if (frozen is AudioStreamingBody.PlaybackComplete) _sealed = true;
            WakeLocked();
            return pending.Sent.Task;
        }
    }

    // Seal and drain controls only. This does not generate playbackComplete or infer
    // source/native completion. A queued playbackComplete seals automatically.
    internal Task DrainAsync()
    {
        lock (_gate) { _sealed = true; WakeLocked(); }
        return _run;
    }

    private async Task RunAsync()
    {
        try
        {
            while (true)
            {
                Pending? item; Task changed;
                lock (_gate)
                {
                    if (_failure is { } failure) ExceptionDispatchInfo.Capture(failure).Throw();
                    _token.ThrowIfCancellationRequested();
                    if (_queue.Count == 0 && _sealed) { _finished = true; return; }
                    // Required controls always precede advisory progress. The same
                    // worker and actual transport admission own both kinds of frame.
                    if (_queue.Count != 0) { item = _queue[0]; _queue.RemoveAt(0); }
                    else item = FileProgressDue() ? new(new AudioStreamingBody.FileOutputProgress(_latestFileProgress)) : null;
                    if (item is not null) _sending = item;
                    changed = _changed.Task;
                }
                if (item is null) { await changed.WaitAsync(_token).ConfigureAwait(false); continue; }
                RequireEffect();
                await _session.SendAudioReplyAsync(_inbox, new(_inbox.StreamId, item.Body), RequireEffect, _token).ConfigureAwait(false);
                RequireEffect(); // A decision is not current just because an already admitted frame finished.
                lock (_gate)
                {
                    if (_failure is { } failure) ExceptionDispatchInfo.Capture(failure).Throw();
                    _sending = null;
                    if (item.Body is AudioStreamingBody.FileOutputProgress progress)
                    {
                        _sentFileProgress = progress.SourceFrames;
                        _fileProgressSentAt = _time.GetTimestamp();
                    }
                    item.Sent.TrySetResult();
                }
            }
        }
        catch (Exception error)
        {
            Exception final;
            lock (_gate)
            {
                final = _disposeReason is not null && ReferenceEquals(_failure, _disposeReason) && IsOwnedCancellation(error)
                    ? _disposeReason
                    : _failure is { } prior && !ReferenceEquals(prior, error)
                    ? new AggregateException("Audio control delivery failed after the writer was stopped.", prior, error) : error;
                FailLocked(final);
                _sending?.Fail(final);
                _sending = null; _finished = true;
            }
            ExceptionDispatchInfo.Capture(final).Throw();
        }
        finally { _lifetime.Dispose(); }
    }

    // Safe at the shared TCP admission boundary: no queue, carrier or account-cache
    // lock. Local disposal prevents a queued frame from being admitted. A frame
    // already admitted may finish; do not interrupt its prefix/body and corrupt MAIN.
    private void RequireEffect()
    {
        if (Volatile.Read(ref _failure) is { } failure) ExceptionDispatchInfo.Capture(failure).Throw();
        _permission.RequireEffectCurrent(_inbox, _inbox.Source, _permission.Request.OutputEndpointId);
        // Optional owner deadline, also checked after waiting for the shared TCP
        // writer. Like the permission check, this must be lock-free and nonblocking.
        _requireSessionEffect?.Invoke();
        if (Volatile.Read(ref _failure) is { } ended) ExceptionDispatchInfo.Capture(ended).Throw();
    }
    private void FailLocked(Exception failure)
    {
        Volatile.Write(ref _failure, failure); _sealed = true;
        foreach (var item in _queue) item.Fail(failure);
        _queue.Clear(); WakeLocked();
    }
    private void WakeLocked()
    {
        var changed = _changed; _changed = Signal(); changed.TrySetResult();
    }
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool IsOwnedCancellation(Exception error) => error is OperationCanceledException { InnerException: null } canceled &&
        ((_token.IsCancellationRequested && canceled.CancellationToken == _token) ||
         (_callerToken.IsCancellationRequested && canceled.CancellationToken == _callerToken));

    public async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (!_finished && _failure is null)
            {
                _disposeReason = new OperationCanceledException("The audio receiver control writer was closed.");
                FailLocked(_disposeReason);
            }
        }
        try { await _run.ConfigureAwait(false); }
        catch (OperationCanceledException) when (_disposeReason is not null && ReferenceEquals(Volatile.Read(ref _failure), _disposeReason)) { }
        // Completion still exposes operation cancellation. After the actual writer
        // has ended, its own expected cancellation is not a resource-close failure.
        // A foreign token or any nested cleanup cause must continue to propagate.
        catch (OperationCanceledException error) when (IsOwnedCancellation(error)) { }
    }
    private sealed class Pending(AudioStreamingBody body)
    {
        internal AudioStreamingBody Body = body;
        internal readonly TaskCompletionSource Sent = Signal();
        internal void Fail(Exception failure)
        {
            if (Sent.TrySetException(failure))
                // Completion is the owner's mandatory aggregate failure channel; a
                // real-time producer need not keep every superseded credit task alive.
                // Individual delivery tasks remain faulted and preserve the same cause.
                _ = Sent.Task.Exception;
        }
    }
}
