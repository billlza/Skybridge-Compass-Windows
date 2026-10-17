using System.Runtime.ExceptionServices;

namespace Skybridge.WinClient.Services;

internal enum WindowDialogResult { None, Primary, Secondary }
internal interface IWindowDialogOperation
{
    Task<WindowDialogResult> ShowAsync();
    void Hide();
}

/// <summary>One modal owner per window, shared by feature prompts. Queued UI callbacks
/// retain their bounded slot until dequeued. Cancellation closes the exact dialog on
/// its UI context and waits for the real ShowAsync operation before returning.</summary>
internal sealed class WindowDialogCoordinator : IAsyncDisposable
{
    internal const int Capacity = 4;
    private readonly object _gate = new();
    private readonly Func<Action, bool> _enqueue;
    private readonly SemaphoreSlim _modal = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly CancellationToken _lifetimeToken;
    private readonly HashSet<Pending> _pending = [];
    private readonly TimeSpan _shutdownTimeout;
    private Task? _closing;
    private bool _closed, _disposed;

    internal WindowDialogCoordinator(Func<Action, bool> enqueue, TimeSpan? shutdownTimeout = null)
    {
        _enqueue = enqueue ?? throw new ArgumentNullException(nameof(enqueue));
        _lifetimeToken = _lifetime.Token;
        _shutdownTimeout = shutdownTimeout ?? TimeSpan.FromSeconds(30);
        if (_shutdownTimeout <= TimeSpan.Zero || _shutdownTimeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
    }
    internal int PendingCount { get { lock (_gate) return _pending.Count; } }

    internal Task<WindowDialogResult> ShowAsync(Func<IWindowDialogOperation> create, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(create); cancellationToken.ThrowIfCancellationRequested();
        Pending request;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_pending.Count >= Capacity) throw new InvalidOperationException("The window's bounded dialog queue is full.");
            request = new(create, cancellationToken, _lifetimeToken); _pending.Add(request);
        }
        try
        {
            if (!_enqueue(() => Execute(request)))
                throw new InvalidOperationException("The window cannot dispatch the dialog request.");
        }
        catch (Exception error) { Complete(request, null, error); }
        return request.Result.Task;
    }

    // Dispatcher callback: all failures are delivered through the retained request.
    private async void Execute(Pending request)
    {
        bool entered = false; WindowDialogResult? result = null; Exception? failure = null;
        try
        {
            await _modal.WaitAsync(request.Token); entered = true;
            request.Token.ThrowIfCancellationRequested();
            var dialog = request.Create() ?? throw new InvalidOperationException("No dialog operation was created.");
            request.Token.ThrowIfCancellationRequested();
            var showing = dialog.ShowAsync() ?? throw new InvalidOperationException("No dialog completion operation was returned.");
            var hideFailure = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (request.Token.Register(() =>
            {
                if (showing.IsCompleted) return;
                try
                {
                    if (!_enqueue(() =>
                    {
                        try { if (!showing.IsCompleted) dialog.Hide(); }
                        catch (Exception error) { hideFailure.TrySetResult(error); }
                    })) hideFailure.TrySetResult(new InvalidOperationException("The window cannot dispatch dialog cancellation."));
                }
                catch (Exception error) { hideFailure.TrySetResult(error); }
            }))
            {
                try { result = await showing; }
                catch (Exception error) { failure = error; }
            }
            // Even a failed Hide never releases the modal slot before ShowAsync has
            // really completed. A late callback only targets this exact operation.
            if (hideFailure.Task.IsCompletedSuccessfully)
                failure = failure is null ? hideFailure.Task.Result : new AggregateException(failure, hideFailure.Task.Result);
            if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
            request.Token.ThrowIfCancellationRequested();
        }
        catch (Exception error) { failure = error; }
        finally
        {
            if (entered) _modal.Release();
            Complete(request, result, failure);
        }
    }

    private void Complete(Pending request, WindowDialogResult? result, Exception? failure)
    {
        // Enqueue contracts return false only when the callback was not accepted.
        // Retain a defensive single-completion guard for synchronous dispatchers.
        if (Interlocked.Exchange(ref request.Completed, 1) != 0) return;
        CancellationToken? canceledToken = failure is OperationCanceledException { InnerException: null } canceled &&
            canceled.CancellationToken == request.Token && request.Token.IsCancellationRequested
            ? request.Caller.IsCancellationRequested ? request.Caller : _lifetimeToken : null;
        request.Scope.Dispose();
        lock (_gate) _pending.Remove(request);
        request.Drained.TrySetResult();
        if (canceledToken is { } token) request.Result.TrySetCanceled(token);
        else if (failure is not null) request.Result.TrySetException(failure);
        else if (result is { } actual) request.Result.TrySetResult(actual);
        else request.Result.TrySetException(new InvalidOperationException("Dialog ended without a result or failure."));
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed) return ValueTask.CompletedTask;
            _closed = true;
            if (_closing is null || _closing.IsFaulted) _closing = CloseAsync(_pending.Select(item => item.Drained.Task).ToArray());
            return new(_closing);
        }
    }
    private async Task CloseAsync(Task[] pending)
    {
        // Do not invoke callbacks while holding the caller's monitor synchronously.
        await Task.Yield();
        Exception? cancellationFailure = null;
        try { _lifetime.Cancel(); } catch (Exception error) { cancellationFailure = error; }
        try { await Task.WhenAll(pending).WaitAsync(_shutdownTimeout).ConfigureAwait(false); }
        catch (Exception error)
        {
            if (cancellationFailure is not null) throw new AggregateException(cancellationFailure, error);
            throw;
        }
        if (cancellationFailure is not null) ExceptionDispatchInfo.Capture(cancellationFailure).Throw();
        lock (_gate)
        {
            _lifetime.Dispose(); _modal.Dispose(); _disposed = true;
        }
    }
    private sealed class Pending(Func<IWindowDialogOperation> create, CancellationToken caller, CancellationToken lifetime)
    {
        internal Func<IWindowDialogOperation> Create { get; } = create;
        internal CancellationToken Caller { get; } = caller;
        internal CancellationTokenSource Scope { get; } = CancellationTokenSource.CreateLinkedTokenSource(caller, lifetime);
        internal CancellationToken Token => Scope.Token;
        internal int Completed;
        internal TaskCompletionSource<WindowDialogResult> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Drained { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
