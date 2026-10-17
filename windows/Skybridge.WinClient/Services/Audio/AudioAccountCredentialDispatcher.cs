namespace Skybridge.WinClient.Services.Audio;

/// <summary>One bounded credential request on the account owner's UI context. A canceled
/// queued callback retains its slot until dequeued; executing account cleanup is awaited.</summary>
internal sealed class AudioAccountCredentialDispatcher : IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly Func<Action, bool> _enqueue;
    private readonly Func<AccountAudioAuthorization, CancellationToken, Task<AccountDeviceAuthentication>> _authenticate;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly CancellationToken _lifetimeToken;
    private readonly TimeSpan _shutdownTimeout;
    private TaskCompletionSource? _stopped;
    private Pending? _pending;
    private bool _closed;
    private bool _disposed;

    internal AudioAccountCredentialDispatcher(Func<Action, bool> enqueue,
        Func<AccountAudioAuthorization, CancellationToken, Task<AccountDeviceAuthentication>> authenticate,
        TimeSpan? shutdownTimeout = null)
    {
        _enqueue = enqueue ?? throw new ArgumentNullException(nameof(enqueue));
        _authenticate = authenticate ?? throw new ArgumentNullException(nameof(authenticate));
        _lifetimeToken = _lifetime.Token;
        _shutdownTimeout = shutdownTimeout ?? TimeSpan.FromSeconds(30);
        if (_shutdownTimeout <= TimeSpan.Zero || _shutdownTimeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
    }

    internal async Task<AccountDeviceAuthentication> AuthenticateAsync(AccountAudioAuthorization epoch, CancellationToken cancellationToken)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetimeToken);
        var token = lifetime.Token;
        token.ThrowIfCancellationRequested(); epoch.RequireCurrent();
        Pending request;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_pending is not null) throw new InvalidOperationException("An audio account callback is still queued or executing.");
            request = new(epoch, token); _pending = request;
        }
        using var registration = token.Register(() =>
        {
            if (Interlocked.CompareExchange(ref request.State, 2, 0) == 0) request.Result.TrySetCanceled(token);
        });
        bool queued = false;
        try
        {
            token.ThrowIfCancellationRequested();
            if (!_enqueue(() => Execute(request))) throw new InvalidOperationException("The account window dispatcher is unavailable.");
            queued = true;
            return await request.Result.Task.ConfigureAwait(false);
        }
        finally { if (!queued) Complete(request); }
    }

    // This is a native dispatcher callback. All failures become the requesting task's result.
    private async void Execute(Pending request)
    {
        try
        {
            if (Interlocked.CompareExchange(ref request.State, 1, 0) != 0) return;
            request.Token.ThrowIfCancellationRequested(); request.Epoch.RequireCurrent();
            var authentication = await _authenticate(request.Epoch, request.Token).ConfigureAwait(true);
            request.Token.ThrowIfCancellationRequested(); request.Epoch.RequireAuthentication(authentication);
            Complete(request);
            request.Result.TrySetResult(authentication);
        }
        catch (OperationCanceledException) when (request.Token.IsCancellationRequested) { Complete(request); request.Result.TrySetCanceled(request.Token); }
        catch (Exception failure) { Complete(request); request.Result.TrySetException(failure); }
        finally { Complete(request); }
    }
    private void Complete(Pending request)
    {
        lock (_gate) { if (ReferenceEquals(_pending, request)) _pending = null; }
        request.Drained.TrySetResult();
    }

    public async ValueTask DisposeAsync()
    {
        Task? draining = null;
        TaskCompletionSource stopped;
        lock (_gate)
        {
            if (_disposed) return;
            _closed = true;
            if (_stopped is null || _stopped.Task.IsFaulted)
            {
                _stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
                draining = _pending?.Drained.Task ?? Task.CompletedTask;
            }
            stopped = _stopped;
        }
        if (draining is null) { await stopped.Task.ConfigureAwait(false); return; }
        try
        {
            _lifetime.Cancel();
            await draining.WaitAsync(_shutdownTimeout).ConfigureAwait(false);
            _lifetime.Dispose();
            lock (_gate) _disposed = true;
            stopped.TrySetResult();
        }
        catch (Exception failure) { stopped.TrySetException(failure); }
        await stopped.Task.ConfigureAwait(false);
    }

    private sealed class Pending(AccountAudioAuthorization epoch, CancellationToken token)
    {
        internal AccountAudioAuthorization Epoch { get; } = epoch;
        internal CancellationToken Token { get; } = token;
        internal int State; // queued, executing, canceled before execution
        internal TaskCompletionSource<AccountDeviceAuthentication> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Drained { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
