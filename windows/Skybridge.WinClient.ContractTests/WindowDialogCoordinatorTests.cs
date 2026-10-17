using System.Collections.Concurrent;
using Skybridge.WinClient.Services;

internal static class WindowDialogCoordinatorTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("window dialogs serialize different features on the same UI context", Serial),
        ("window dialog cancellation waits for actual closure before another prompt", Cancellation),
        ("window dialog cancellation preserves Hide and Show failures without releasing early", HideFailure),
        ("window dialog queued cancellation retains bounded slots until UI dequeue", QueuedCancellation),
        ("window dialog dispatch rejection cannot create a hidden prompt", DispatchFailure),
        ("window dialog shutdown timeout retains the active owner until actual drain", ShutdownTimeout),
        ("window dialog preserves foreign cancellation and nested failure causes", ForeignCancellation)
    ];
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(3);
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed class Ui : IAsyncDisposable
    {
        private readonly BlockingCollection<Action> _queue = new();
        private readonly Thread _thread;
        private readonly TaskCompletionSource _ready = Signal();
        private Exception? _failure;
        internal volatile bool Accept = true;
        internal int ThreadId;
        internal Ui()
        {
            _thread = new(() =>
            {
                ThreadId = Environment.CurrentManagedThreadId;
                SynchronizationContext.SetSynchronizationContext(new Context(this)); _ready.SetResult();
                foreach (var action in _queue.GetConsumingEnumerable())
                    try { action(); } catch (Exception error) { Interlocked.CompareExchange(ref _failure, error, null); }
            }) { IsBackground = true, Name = "Dialog contract UI" };
            _thread.Start(); _ready.Task.GetAwaiter().GetResult();
        }
        internal bool Enqueue(Action action) { if (!Accept) return false; _queue.Add(action); return true; }
        internal Task Invoke(Action action)
        {
            var done = Signal();
            _queue.Add(() => { try { action(); done.SetResult(); } catch (Exception error) { done.SetException(error); } });
            return done.Task.WaitAsync(Limit);
        }
        public async ValueTask DisposeAsync()
        {
            _queue.CompleteAdding(); await Task.Run(_thread.Join).WaitAsync(Limit); _queue.Dispose();
            if (_failure is { } failure) throw new Exception("The controlled UI context had an unhandled callback.", failure);
        }
        private sealed class Context(Ui ui) : SynchronizationContext
        { public override void Post(SendOrPostCallback callback, object? state) => ui._queue.Add(() => callback(state)); }
    }
    private sealed class Dialog(Ui ui) : IWindowDialogOperation
    {
        internal readonly TaskCompletionSource Shown = Signal(), Hidden = Signal();
        internal readonly TaskCompletionSource<WindowDialogResult> Closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Exception? HideError;
        internal int ShowCalls, HideCalls;
        public Task<WindowDialogResult> ShowAsync()
        {
            Check(); ShowCalls++; Shown.TrySetResult(); return Closed.Task;
        }
        public void Hide()
        {
            Check(); HideCalls++; Hidden.TrySetResult(); if (HideError is { } error) throw error;
            // The test chooses when the actual native close completes.
        }
        private void Check() => Require(Environment.CurrentManagedThreadId == ui.ThreadId, "A dialog escaped its UI context.");
    }
    private static async Task Serial()
    {
        await using var ui = new Ui(); await using var owner = new WindowDialogCoordinator(ui.Enqueue);
        var first = new Dialog(ui); var second = new Dialog(ui);
        var one = owner.ShowAsync(() => first, default); var two = owner.ShowAsync(() => second, default);
        await first.Shown.Task.WaitAsync(Limit); await ui.Invoke(() => { });
        Require(!second.Shown.Task.IsCompleted && owner.PendingCount == 2, "Two feature dialogs overlapped.");
        await ui.Invoke(() => first.Closed.SetResult(WindowDialogResult.Primary));
        Require(await one.WaitAsync(Limit) == WindowDialogResult.Primary, "The first feature lost its actual decision.");
        await second.Shown.Task.WaitAsync(Limit); await ui.Invoke(() => second.Closed.SetResult(WindowDialogResult.None));
        Require(await two.WaitAsync(Limit) == WindowDialogResult.None && owner.PendingCount == 0, "The second feature lost closure or retained admission.");
    }
    private static async Task Cancellation()
    {
        await using var ui = new Ui(); await using var owner = new WindowDialogCoordinator(ui.Enqueue);
        using var cancel = new CancellationTokenSource(); var first = new Dialog(ui); var next = new Dialog(ui);
        var pending = owner.ShowAsync(() => first, cancel.Token); await first.Shown.Task.WaitAsync(Limit);
        cancel.Cancel(); await first.Hidden.Task.WaitAsync(Limit);
        var replacement = owner.ShowAsync(() => next, default); await ui.Invoke(() => { });
        Require(!pending.IsCompleted && !next.Shown.Task.IsCompleted && owner.PendingCount == 2,
            "Cancellation abandoned the still-visible prompt or admitted its replacement.");
        await ui.Invoke(() => first.Closed.SetResult(WindowDialogResult.None));
        var error = await Throws<OperationCanceledException>(() => pending.WaitAsync(Limit));
        Require(error.CancellationToken == cancel.Token, "Clean cancellation lost the caller's token.");
        await next.Shown.Task.WaitAsync(Limit); await ui.Invoke(() => next.Closed.SetResult(WindowDialogResult.Secondary));
        Require(await replacement.WaitAsync(Limit) == WindowDialogResult.Secondary && first.HideCalls == 1, "A late hide touched the replacement.");
    }
    private static async Task HideFailure()
    {
        await using var ui = new Ui(); await using var owner = new WindowDialogCoordinator(ui.Enqueue);
        using var cancel = new CancellationTokenSource(); var hide = new IOException("hide failed"); var show = new IOException("show cleanup failed");
        var dialog = new Dialog(ui) { HideError = hide };
        var result = owner.ShowAsync(() => dialog, cancel.Token); await dialog.Shown.Task.WaitAsync(Limit);
        cancel.Cancel(); await dialog.Hidden.Task.WaitAsync(Limit); await ui.Invoke(() => { });
        Require(!result.IsCompleted && owner.PendingCount == 1, "Failed Hide released the actual active prompt.");
        await ui.Invoke(() => dialog.Closed.SetException(show));
        var failure = await Throws<AggregateException>(() => result.WaitAsync(Limit));
        Require(failure.InnerExceptions.Contains(show) && failure.InnerExceptions.Contains(hide) && owner.PendingCount == 0,
            "Dialog failure lost its native or cancellation-cleanup cause.");
    }
    private static async Task QueuedCancellation()
    {
        await using var ui = new Ui(); await using var owner = new WindowDialogCoordinator(ui.Enqueue);
        using var release = new ManualResetEventSlim(); var entered = Signal();
        ui.Enqueue(() => { entered.SetResult(); release.Wait(); }); await entered.Task.WaitAsync(Limit);
        using var cancel = new CancellationTokenSource(); int created = 0;
        var requests = Enumerable.Range(0, WindowDialogCoordinator.Capacity)
            .Select(_ => owner.ShowAsync(() => { created++; return new Dialog(ui); }, cancel.Token)).ToArray();
        try
        {
            cancel.Cancel();
            await Throws<InvalidOperationException>(() => Call(() => owner.ShowAsync(() => new Dialog(ui), default)));
            Require(requests.All(task => !task.IsCompleted) && owner.PendingCount == WindowDialogCoordinator.Capacity,
                "Canceled queued callbacks released their admission before actual dequeue.");
        }
        finally { release.Set(); }
        foreach (var request in requests) await Throws<OperationCanceledException>(() => request.WaitAsync(Limit));
        Require(created == 0 && owner.PendingCount == 0, "Canceled queued work created a prompt or retained slots after dequeue.");
    }
    private static async Task DispatchFailure()
    {
        await using var ui = new Ui(); await using var owner = new WindowDialogCoordinator(ui.Enqueue);
        ui.Accept = false; int created = 0;
        await Throws<InvalidOperationException>(() => owner.ShowAsync(() => { created++; return new Dialog(ui); }, default));
        Require(created == 0 && owner.PendingCount == 0, "Rejected dispatch created a dialog or retained a nonexistent callback.");
        ui.Accept = true;
    }
    private static async Task ShutdownTimeout()
    {
        await using var ui = new Ui(); var owner = new WindowDialogCoordinator(ui.Enqueue, TimeSpan.FromMilliseconds(30));
        var dialog = new Dialog(ui); var result = owner.ShowAsync(() => dialog, default); await dialog.Shown.Task.WaitAsync(Limit);
        await Throws<TimeoutException>(() => owner.DisposeAsync().AsTask());
        Require(!result.IsCompleted && owner.PendingCount == 1, "Shutdown timeout discarded the native prompt owner.");
        await Throws<ObjectDisposedException>(() => Call(() => owner.ShowAsync(() => new Dialog(ui), default)));
        await ui.Invoke(() => dialog.Closed.SetResult(WindowDialogResult.None));
        await Throws<OperationCanceledException>(() => result.WaitAsync(Limit));
        await owner.DisposeAsync(); Require(owner.PendingCount == 0, "Real closure did not allow disposal to finish.");
    }
    private static async Task ForeignCancellation()
    {
        foreach (bool nested in new[] { false, true })
        {
            await using var ui = new Ui(); await using var owner = new WindowDialogCoordinator(ui.Enqueue);
            using var foreign = new CancellationTokenSource(); foreign.Cancel();
            var failure = new OperationCanceledException("foreign native cancellation", nested ? new IOException("cleanup") : null, foreign.Token);
            var dialog = new Dialog(ui); var result = owner.ShowAsync(() => dialog, default);
            await dialog.Shown.Task.WaitAsync(Limit); await ui.Invoke(() => dialog.Closed.SetException(failure));
            Require(ReferenceEquals(failure, await Throws<OperationCanceledException>(() => result.WaitAsync(Limit))),
                "Dialog ownership replaced a foreign cancellation or swallowed its nested cause.");
        }
    }
    private static Task Call(Action action) { action(); return Task.CompletedTask; }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string reason) { if (!condition) throw new Exception(reason); }
}
