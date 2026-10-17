using System.Runtime.ExceptionServices;
using System.Text;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioPlaybackApprovalFailure { Busy, Declined, TimedOut, ClockChanged, Revoked }
internal sealed class AudioPlaybackApprovalException(AudioPlaybackApprovalFailure reason)
    : IOException($"Audio playback approval: {reason}.")
{
    internal AudioPlaybackApprovalFailure Reason { get; } = reason;
}

internal sealed class AudioPlaybackApprovalRequest
{
    private readonly ILanAudioStreamInbox _inbox;
    private readonly AccountAudioMembershipLease _membership;
    internal AudioPlaybackApprovalRequest(ILanAudioStreamInbox inbox, AccountAudioMembershipLease membership, string outputEndpointId)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        ArgumentNullException.ThrowIfNull(membership);
        if (string.IsNullOrWhiteSpace(outputEndpointId) || outputEndpointId.Contains('\0') || Encoding.UTF8.GetByteCount(outputEndpointId) > 4096)
            throw new InvalidDataException("Playback approval requires an explicit bounded output endpoint ID.");
        membership.RequireInbox(inbox);
        _inbox = inbox; _membership = membership;
        Source = inbox.Source; OutputEndpointId = outputEndpointId;
        RequireCurrent();
    }
    internal Guid Id { get; } = Guid.NewGuid();
    internal Guid StreamId => _inbox.StreamId;
    internal string SessionId => _membership.SessionId;
    internal Guid MembershipId => _membership.Evidence.Id;
    internal AudioDeviceIdentity Sender => _membership.Evidence.Peer;
    internal AudioPlaybackSource Source { get; }
    internal string OutputEndpointId { get; }
    internal void RequireCurrent() => _membership.RequireCurrent();
    internal void RequireEffectCurrent() => _membership.RequireEffectCurrent();
    internal void RequireTarget(ILanAudioStreamInbox inbox, AudioPlaybackSource source, string outputEndpointId)
    {
        if (!ReferenceEquals(inbox, _inbox) || source != Source || outputEndpointId != OutputEndpointId)
            throw new InvalidDataException("Playback permission does not match this exact stream, source and output.");
    }
}

// Only local one-stream consent. Every effect also checks the original membership
// and stream owner; a new account lease cannot extend or inherit this permission.
internal sealed class AudioPlaybackPermission
{
    private int _revoked;
    private readonly CancellationToken _caller, _service;
    internal AudioPlaybackPermission(AudioPlaybackApprovalRequest request, CancellationToken caller, CancellationToken service)
    { Request = request; _caller = caller; _service = service; }
    internal AudioPlaybackApprovalRequest Request { get; }
    internal void Revoke() => Interlocked.Exchange(ref _revoked, 1);
    internal void RequireCurrent(ILanAudioStreamInbox inbox, AudioPlaybackSource source, string outputEndpointId)
    {
        RequireApproved(); Request.RequireTarget(inbox, source, outputEndpointId);
        Request.RequireCurrent(); RequireApproved();
    }
    // No UI, carrier or cache lock. Recheck immediately at the shared writer or
    // native submit boundary. This cannot retract already admitted I/O.
    internal void RequireEffectCurrent(ILanAudioStreamInbox inbox, AudioPlaybackSource source, string outputEndpointId)
    {
        RequireApproved(); Request.RequireTarget(inbox, source, outputEndpointId);
        Request.RequireEffectCurrent(); RequireApproved();
    }
    private void RequireApproved()
    {
        _caller.ThrowIfCancellationRequested(); _service.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _revoked) != 0) throw new AudioPlaybackApprovalException(AudioPlaybackApprovalFailure.Revoked);
    }
}

internal interface IAudioPlaybackApprovalPresenter
{
    // Complete only when this exact prompt has really closed, including cancellation
    // cleanup. Never resolve a new prompt using a previous request's button callback.
    Task<bool> ShowAsync(AudioPlaybackApprovalRequest request, CancellationToken cancellationToken);
}

/// <summary>One bounded approval prompt. The slot remains owned until the presenter's
/// actual task ends, even if it ignores cancellation. No detached UI or replacement
/// prompt is allowed to turn a late response into permission.</summary>
internal sealed class AudioPlaybackApprovalService : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly IAudioPlaybackApprovalPresenter _presenter;
    private readonly Func<AudioAuthorizationTime> _clock;
    private readonly long _timeoutMilliseconds;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly CancellationToken _lifetimeToken;
    private readonly TaskCompletionSource _disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Pending? _pending;
    private bool _closed;

    internal AudioPlaybackApprovalService(IAudioPlaybackApprovalPresenter presenter,
        Func<AudioAuthorizationTime>? clock = null, TimeSpan? decisionTimeout = null)
    {
        _presenter = presenter ?? throw new ArgumentNullException(nameof(presenter));
        _clock = clock ?? AudioAuthorizationTime.ReadWindows;
        var timeout = decisionTimeout ?? TimeSpan.FromSeconds(60);
        if (timeout < TimeSpan.FromMilliseconds(1) || timeout > TimeSpan.FromSeconds(60))
            throw new ArgumentOutOfRangeException(nameof(decisionTimeout));
        _timeoutMilliseconds = checked((long)Math.Ceiling(timeout.TotalMilliseconds));
        _lifetimeToken = _lifetime.Token;
    }

    internal async Task<AudioPlaybackPermission> RequestAsync(ILanAudioStreamInbox inbox,
        AccountAudioMembershipLease membership, string outputEndpointId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var request = new AudioPlaybackApprovalRequest(inbox, membership, outputEndpointId);
        Pending pending;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_pending is not null) throw new AudioPlaybackApprovalException(AudioPlaybackApprovalFailure.Busy);
            var started = _clock();
            if (started.WallMilliseconds <= 0 || started.ContinuousMilliseconds < 0)
                throw new AudioPlaybackApprovalException(AudioPlaybackApprovalFailure.ClockChanged);
            pending = new(request, started, cancellationToken, _lifetimeToken);
            _pending = pending;
        }
        Task<bool>? presentation = null;
        Task? watcher = null;
        using var watchStop = CancellationTokenSource.CreateLinkedTokenSource(pending.Cancellation.Token);
        var errors = new List<Exception>();
        try
        {
            try
            {
                RequireCurrent(pending);
                watcher = WatchAsync(pending, watchStop.Token);
                // Ownership is installed before invoking even a synchronous presenter.
                presentation = _presenter.ShowAsync(request, pending.Cancellation.Token)
                    ?? throw new InvalidOperationException("Audio approval presenter returned no task.");
                if (await Task.WhenAny(presentation, watcher).ConfigureAwait(false) == watcher)
                    await watcher.ConfigureAwait(false); // Watcher only ends by cancellation/failure.
                bool allowed = await presentation.ConfigureAwait(false);
                RequireCurrent(pending);
                if (!allowed) throw new AudioPlaybackApprovalException(AudioPlaybackApprovalFailure.Declined);
            }
            catch (Exception error) { Add(error); }

            // A failed operation cancels its UI but keeps the slot until actual cleanup.
            if (errors.Count != 0) Cancel(pending.Cancellation);
            Cancel(watchStop);
            if (watcher is not null)
            {
                try { await watcher.ConfigureAwait(false); }
                catch (OperationCanceledException error) when (error.InnerException is null &&
                    error.CancellationToken == watchStop.Token && watchStop.IsCancellationRequested) { }
                catch (Exception error) { Add(error); }
            }
            if (presentation is not null)
            {
                try { await presentation.ConfigureAwait(false); }
                catch (OperationCanceledException error) when (errors.Count != 0 && error.InnerException is null &&
                    error.CancellationToken == pending.Cancellation.Token && pending.Cancellation.IsCancellationRequested) { }
                catch (Exception error) { Add(error); }
            }
            if (errors.Count == 1) ExceptionDispatchInfo.Capture(errors[0]).Throw();
            if (errors.Count > 1) throw new AggregateException("Audio approval failed and cleanup reported additional errors.", errors);
            RequireCurrent(pending); // Covers decision-to-delivery cancellation/replacement.
            return new(request, cancellationToken, _lifetimeToken);
        }
        finally
        {
            pending.Cancellation.Dispose();
            lock (_gate) if (ReferenceEquals(_pending, pending)) _pending = null;
            pending.Drained.TrySetResult();
        }
        void Add(Exception error) { if (!errors.Any(existing => ReferenceEquals(existing, error))) errors.Add(error); }
        void Cancel(CancellationTokenSource source) { try { source.Cancel(); } catch (Exception error) { Add(error); } }
    }

    private async Task WatchAsync(Pending pending, CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = RequireCurrent(pending);
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(100, remaining)), cancellationToken).ConfigureAwait(false);
        }
    }
    private long RequireCurrent(Pending pending)
    {
        pending.Caller.ThrowIfCancellationRequested(); _lifetimeToken.ThrowIfCancellationRequested();
        pending.Request.RequireCurrent();
        var now = _clock();
        if (now.WallMilliseconds < pending.Started.WallMilliseconds || now.ContinuousMilliseconds < pending.Started.ContinuousMilliseconds)
            throw new AudioPlaybackApprovalException(AudioPlaybackApprovalFailure.ClockChanged);
        long elapsed = Math.Max(now.WallMilliseconds - pending.Started.WallMilliseconds,
            now.ContinuousMilliseconds - pending.Started.ContinuousMilliseconds);
        if (elapsed >= _timeoutMilliseconds) throw new AudioPlaybackApprovalException(AudioPlaybackApprovalFailure.TimedOut);
        pending.Caller.ThrowIfCancellationRequested(); _lifetimeToken.ThrowIfCancellationRequested();
        return _timeoutMilliseconds - elapsed;
    }

    public async ValueTask DisposeAsync()
    {
        Pending? pending; bool first;
        lock (_gate) { first = !_closed; _closed = true; pending = _pending; }
        if (!first) { await _disposed.Task.ConfigureAwait(false); return; }
        Exception? cancellationError = null;
        try
        {
            try { _lifetime.Cancel(); } catch (Exception error) { cancellationError = error; }
            if (pending is not null) await pending.Drained.Task.ConfigureAwait(false);
            _lifetime.Dispose();
            if (cancellationError is not null) ExceptionDispatchInfo.Capture(cancellationError).Throw();
            _disposed.TrySetResult();
        }
        catch (Exception error) { _disposed.TrySetException(error); }
        await _disposed.Task.ConfigureAwait(false);
    }
    private sealed class Pending(AudioPlaybackApprovalRequest request, AudioAuthorizationTime started,
        CancellationToken caller, CancellationToken lifetime)
    {
        internal AudioPlaybackApprovalRequest Request { get; } = request;
        internal AudioAuthorizationTime Started { get; } = started;
        internal CancellationToken Caller { get; } = caller;
        internal CancellationTokenSource Cancellation { get; } = CancellationTokenSource.CreateLinkedTokenSource(caller, lifetime);
        internal TaskCompletionSource Drained { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
