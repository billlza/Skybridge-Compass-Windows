namespace Skybridge.WinClient.Services.Audio;

internal sealed record AudioReceiveHostSnapshot(bool Enabled, bool Stopping, int ConnectedDevices, int ListeningDevices,
    string? OutputEndpointId, string? PeerName, AudioCaptureReceivePhase? Phase,
    Exception? Failure, bool NativeReleaseConfirmed, bool NativeReleaseUnconfirmed,
    AudioMembershipRenewalSnapshot? Renewal);

/// <summary>Product owner of audio reception on at most eight existing MAIN
/// sessions. Idle peers wait asynchronously. At most one offer owns approval and
/// native output; a new offer never preempts playback or an uncertain native close.</summary>
internal sealed class AudioReceiveHost : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly SemaphoreSlim _commands = new(1, 1);
    private readonly Dictionary<LanProductControlSession, Entry> _sessions = [];
    private readonly Func<LanProductControlSession, string, AudioCaptureReceiveSession> _create;
    private readonly AudioOriginalFileReceiveRegistry? _originalFiles;
    private CancellationTokenSource? _enabled;
    private string? _endpoint;
    private Active? _active;
    private Exception? _lastFailure, _unreleased;
    private bool _stopping, _closed;

    internal AudioReceiveHost(Func<LanProductControlSession, string, AudioCaptureReceiveSession> create,
        AudioOriginalFileReceiveRegistry? originalFiles = null)
    { _create = create ?? throw new ArgumentNullException(nameof(create)); _originalFiles = originalFiles; }

    internal AudioReceiveHostSnapshot ReadSnapshot()
    {
        lock (_gate) return new(_enabled is not null && !_stopping && !_closed && _unreleased is null, _stopping,
            _sessions.Count(item => item.Key.IsReady),
            _sessions.Count(item => item.Value.Listening && item.Key.IsReady),
            _endpoint, _active?.Entry.Session.PeerDisplayName, _active?.Operation?.Phase,
            _unreleased ?? _lastFailure, _unreleased is null && (_active?.Operation?.ResourcesReleaseConfirmed ?? true), _unreleased is not null,
            _active?.Operation?.RenewalSnapshot);
    }

    internal async Task AttachAsync(LanProductControlSession session, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(session);
        await _commands.WaitAsync(token).ConfigureAwait(false);
        try
        {
            Entry entry;
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_closed, this);
                if (_sessions.ContainsKey(session)) return;
                if (!session.IsReady) throw new InvalidOperationException("Audio requires an established device session.");
                if (_sessions.Count >= 8) throw new InvalidOperationException("Eight audio device sessions are already registered.");
                entry = new(session); _sessions.Add(session, entry);
                if (_enabled is not null && _unreleased is null) Start(entry, _enabled.Token, _endpoint!);
            }
            // Attach cancellation cannot discard an installed consumer. The host
            // retains it and the caller can detach/close the actual MAIN owner.
            if (entry.Ready is { } ready) await ready.Task.ConfigureAwait(false);
        }
        finally { _commands.Release(); }
    }

    internal async Task EnableAsync(string endpointId, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(endpointId) || endpointId.Contains('\0'))
            throw new ArgumentException("Choose an explicit output endpoint.", nameof(endpointId));
        await _commands.WaitAsync(token).ConfigureAwait(false);
        try
        {
            Task[] ready;
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_closed, this);
                if (_unreleased is not null) throw new InvalidOperationException("A previous native audio owner has not been released.", _unreleased);
                if (_enabled is not null || _stopping) throw new InvalidOperationException("Stop current audio reception before changing its output.");
                _endpoint = endpointId; _lastFailure = null; _enabled = new();
                var pendingReady = new List<Task>();
                foreach (var entry in _sessions.Values)
                {
                    if (!entry.Session.IsReady) continue;
                    Start(entry, _enabled.Token, endpointId); pendingReady.Add(entry.Ready!.Task);
                }
                ready = pendingReady.ToArray();
            }
            try { await Task.WhenAll(ready).ConfigureAwait(false); }
            catch (Exception failure)
            {
                try { await StopCoreAsync().ConfigureAwait(false); }
                catch (Exception cleanup) { throw new AggregateException(failure, cleanup); }
                throw;
            }
        }
        finally { _commands.Release(); }
    }

    private void Start(Entry entry, CancellationToken enabled, string endpoint)
    {
        entry.Ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        entry.FailureReported = false;
        // Yield before running external adapters while the state gate is held.
        entry.Listener = ListenAsync(entry, enabled, endpoint);
    }
    private async Task<Exception?> ListenAsync(Entry entry, CancellationToken enabled, string endpoint)
    {
        await Task.Yield();
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(enabled, entry.Stop.Token, entry.Session.Lifetime);
        var token = scope.Token;
        Task<ILanAudioStreamInbox>? pending = null;
        Exception? failure = null;
        try
        {
            bool published = false;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                pending = entry.Session.AcceptAudioOfferAsync(token);
                entry.Listening = true;
                if (!published)
                {
                    await entry.Session.SetAudioReceiverCapabilitiesAsync(true,
                        _originalFiles?.ReceiveSupportFor(entry.Session) ?? AudioOriginalFileReceiveSupport.Unavailable, token).ConfigureAwait(false);
                    published = true; entry.Ready!.TrySetResult();
                }
                ILanAudioStreamInbox inbox;
                try { inbox = await pending.ConfigureAwait(false); }
                catch (TimeoutException)
                {
                    // The bounded offer waiter expired with no admitted stream.
                    // Rearm only this idle listener; never retry a playback failure.
                    pending = null; entry.Listening = false; continue;
                }
                catch (LanAudioStreamException error) when (entry.Session.IsReady && error.Reason != AudioStreamingStopReason.SessionReplaced)
                {
                    // Offer -> Stop/overflow can retire the inbox before the
                    // acceptance continuation resumes. That ends this stream,
                    // not the installed consumer on its still-valid MAIN owner.
                    pending = null; entry.Listening = false; lock (_gate) _lastFailure = error; continue;
                }
                pending = null; entry.Listening = false;
                Active? owned;
                lock (_gate)
                {
                    owned = _active is null && _unreleased is null && !token.IsCancellationRequested
                        ? new(entry, endpoint) : null;
                    if (owned is not null) { _active = owned; _lastFailure = null; }
                }
                if (owned is null)
                {
                    try { await entry.Session.SendAudioStopAsync(inbox, AudioStreamingStopReason.ReceiverDeclined, token).ConfigureAwait(false); }
                    finally { inbox.Dispose(); }
                    continue;
                }
                await ReceiveAsync(owned, inbox, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException error) when (error.InnerException is null && token.IsCancellationRequested && error.CancellationToken == token) { }
        catch (LanAudioStreamException) when (!entry.Session.IsReady) { }
        catch (Exception error) { failure = error; }
        finally
        {
            entry.Listening = false;
            try { scope.Cancel(); } catch (Exception error) { Add(error); }
            if (pending is not null)
            {
                try { (await pending.ConfigureAwait(false)).Dispose(); }
                catch (OperationCanceledException error) when (error.InnerException is null && error.CancellationToken == token && token.IsCancellationRequested) { }
                catch (LanAudioStreamException error) when (error.Reason == AudioStreamingStopReason.SessionReplaced && !entry.Session.IsReady) { }
                catch (Exception error) { if (!ReferenceEquals(failure, error)) Add(error); }
            }
            try { await entry.Session.SetAudioReceiverCapabilitiesAsync(false, false, CancellationToken.None).ConfigureAwait(false); }
            catch (Exception error) { Add(error); }
            if (failure is null) entry.Ready!.TrySetCanceled(token.IsCancellationRequested ? token : new CancellationToken(true));
            else entry.Ready!.TrySetException(failure);
            lock (_gate) if (failure is not null) _lastFailure = failure;
        }
        return failure;
        void Add(Exception error) => failure = failure is null ? error : new AggregateException(failure, error);
    }

    private async Task ReceiveAsync(Active active, ILanAudioStreamInbox inbox, CancellationToken token)
    {
        AudioCaptureReceiveSession? operation = null;
        Exception? failure = null;
        bool transferred = false;
        try
        {
            operation = _create(active.Entry.Session, active.Endpoint);
            lock (_gate) active.Operation = operation;
            var running = operation.RunAcceptedAsync(inbox, token); transferred = true;
            await running.ConfigureAwait(false);
        }
        catch (Exception error) { failure = error; }
        finally
        {
            if (!transferred) inbox.Dispose();
            if (operation is not null)
            {
                try { await operation.DisposeAsync().ConfigureAwait(false); }
                catch (Exception error) { if (!ReferenceEquals(failure, error)) failure = failure is null ? error : new AggregateException(failure, error); }
            }
            lock (_gate)
            {
                if (failure is not null) _lastFailure = failure;
                if (operation?.ResourcesReleaseConfirmed == false)
                {
                    _unreleased = failure ?? new IOException("Audio resource release is unconfirmed.");
                    // Keep active.Operation and the original exception/owners alive.
                }
                else if (ReferenceEquals(_active, active)) _active = null;
            }
        }
        if (operation?.ResourcesReleaseConfirmed == false)
        {
            CancellationTokenSource? enabled; lock (_gate) enabled = _enabled;
            try { enabled?.Cancel(); }
            catch (Exception cancellation) { throw new AggregateException(failure ?? _unreleased!, cancellation); }
            throw new InvalidOperationException("Audio reception cannot continue until native output ownership is resolved.", failure);
        }
    }

    internal async Task DetachAsync(LanProductControlSession session)
    {
        await _commands.WaitAsync().ConfigureAwait(false);
        try
        {
            Entry? entry; lock (_gate) _sessions.TryGetValue(session, out entry);
            if (entry is null) return;
            entry.Stop.Cancel();
            var failure = await entry.Listener.ConfigureAwait(false);
            lock (_gate)
            {
                if (_active?.Entry == entry) throw new InvalidOperationException("This device still owns unreleased native audio.", _unreleased);
                _sessions.Remove(session);
            }
            entry.Stop.Dispose();
            if (failure is not null) throw new IOException("The audio device listener ended with a failure.", failure);
        }
        finally { _commands.Release(); }
    }
    internal bool OwnsSession(LanProductControlSession session)
    {
        lock (_gate) return _sessions.ContainsKey(session);
    }
    internal async Task DisableAsync()
    {
        await _commands.WaitAsync().ConfigureAwait(false);
        try { await StopCoreAsync().ConfigureAwait(false); }
        finally { _commands.Release(); }
    }
    private async Task StopCoreAsync()
    {
        CancellationTokenSource? enabled; Entry[] entries;
        lock (_gate) { _stopping = true; enabled = _enabled; entries = _sessions.Values.ToArray(); }
        var errors = new List<Exception>();
        try { enabled?.Cancel(); } catch (Exception error) { errors.Add(error); }
        foreach (var entry in entries)
        {
            var error = await entry.Listener.ConfigureAwait(false);
            if (error is not null && !entry.FailureReported)
            {
                // Deliver a terminal listener failure once to the stop caller;
                // retain it in the task/snapshot. It is not a new close failure on
                // every later disposal after that listener has already drained.
                errors.Add(error); entry.FailureReported = true;
            }
        }
        lock (_gate)
        {
            if (_unreleased is not null) errors.Add(_unreleased);
            else { enabled?.Dispose(); _enabled = null; _endpoint = null; _stopping = false; }
        }
        if (errors.Count > 0) throw new AggregateException("Audio reception stopped with retained failures.", errors);
    }
    public async ValueTask DisposeAsync()
    {
        await _commands.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (_gate) _closed = true;
            await StopCoreAsync().ConfigureAwait(false);
            lock (_gate)
            {
                foreach (var entry in _sessions.Values) entry.Stop.Dispose();
                _sessions.Clear();
            }
        }
        finally { _commands.Release(); }
    }
    private sealed class Entry(LanProductControlSession session)
    {
        internal LanProductControlSession Session { get; } = session;
        internal CancellationTokenSource Stop { get; } = new();
        internal Task<Exception?> Listener = Task.FromResult<Exception?>(null);
        internal TaskCompletionSource? Ready;
        internal bool FailureReported;
        internal volatile bool Listening;
    }
    private sealed class Active(Entry entry, string endpoint)
    {
        internal Entry Entry { get; } = entry;
        internal string Endpoint { get; } = endpoint;
        internal AudioCaptureReceiveSession? Operation;
    }
}
