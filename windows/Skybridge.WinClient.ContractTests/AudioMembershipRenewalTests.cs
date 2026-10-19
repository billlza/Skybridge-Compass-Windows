using System.Collections.Concurrent;
using System.Net.Http;
using Skybridge.WinClient.Services.Audio;

internal static class AudioMembershipRenewalTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("audio renewal commits fresh evidence on its existing consumer and cancels without revoking it", Success),
        ("audio renewal retries only three bounded future slots without extending failed authority", RetrySlots),
        ("audio renewal late admission skips missed retry slots", LateAdmission),
        ("audio renewal timeout stops effects before joining a noncooperative registry request", TimeoutOwnership),
        ("audio renewal arms its deadline before a synchronously blocking request adapter", SynchronousRequest),
        ("audio renewal cancellation owns pending registry cleanup without revoking valid authority", CancellationOwnership),
        ("audio renewal timer cannot revoke the successful request winner", TimerLoses),
        ("audio renewal rejects unchanged evidence and replacement consumers", InvalidSuccess),
        ("audio renewal does not reinterpret unexpected errors as temporary network loss", UnexpectedFailure),
        ("audio renewal checks both clock expiries before requesting again", Expiry)
    ];
    // Real account GET parser/provider and continuation gate with controlled HTTP,
    // time and delay ports. No live account, native timer or hardware claim.
    private sealed class Fixture : IDisposable
    {
        internal readonly AudioAccountMembershipTests.Fixture Account = new();
        internal readonly AudioAccountMembershipTests.Inbox Inbox;
        internal readonly CancellationTokenSource Stop = new();
        internal readonly ManualDelay Delays = new();
        private AccountAudioMembershipLease? _lease;
        internal AccountAudioMembershipLease Lease => _lease ?? throw new InvalidOperationException("Fixture has not acquired a lease.");
        internal AudioMembershipRenewal? Renewal;
        internal Task? Run;
        internal Fixture() { Inbox = new(Account.Binding); }
        internal async Task Start(long remaining = 120_000, Func<CancellationToken, Task<AccountAudioMembershipLease>>? renew = null)
        {
            _lease = await Account.Lease(Inbox);
            Account.Clock.Advance(AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds - remaining);
            Renewal = new(Lease, renew ?? (token => Account.Provider.RenewAsync(Inbox, Lease, token)), Account.Clock.Read, Delays.Delay);
            Run = Renewal.RunAsync(Stop.Token);
        }
        internal async Task Fire(long milliseconds, bool advance = true)
        {
            var delay = await Delays.Next();
            Require((long)delay.Duration.TotalMilliseconds == milliseconds, "Unexpected renewal delay or request budget.");
            if (advance) Account.Clock.Advance(milliseconds);
            delay.Release.TrySetResult();
        }
        public void Dispose() { Stop.Cancel(); Inbox.Dispose(); Account.Dispose(); Stop.Dispose(); }
    }
    internal sealed class ManualDelay
    {
        private readonly ConcurrentQueue<Pending> _pending = new();
        private readonly SemaphoreSlim _available = new(0);
        internal bool IgnoreAttemptCancellation;
        internal async Task Delay(TimeSpan duration, CancellationToken token)
        {
            var pending = new Pending(duration);
            bool ignore = IgnoreAttemptCancellation && duration == TimeSpan.FromSeconds(35);
            using var registration = ignore ? default : token.Register(() => pending.Release.TrySetCanceled(token));
            _pending.Enqueue(pending); _available.Release();
            await pending.Release.Task.ConfigureAwait(false);
        }
        internal async Task<Pending> Next()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            while (true)
            {
                await _available.WaitAsync(timeout.Token);
                if (!_pending.TryDequeue(out var pending)) throw new Exception("Delay queue lost its owner.");
                if (!pending.Release.Task.IsCanceled) return pending;
            }
        }
        internal sealed class Pending(TimeSpan duration)
        {
            internal TimeSpan Duration { get; } = duration;
            internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }
    private static async Task Success()
    {
        using var f = new Fixture(); await f.Start(); var old = f.Lease.Evidence;
        await f.Fire(0);
        await Until(() => f.Renewal!.Snapshot is { State: AudioMembershipRenewalState.Waiting } snapshot && snapshot.Evidence.Id != old.Id);
        var next = await f.Delays.Next();
        Require(next.Duration == TimeSpan.FromMilliseconds(3_480_000) && f.Renewal!.Snapshot.State == AudioMembershipRenewalState.Waiting &&
            f.Renewal.Snapshot.Evidence.Id == f.Lease.Evidence.Id && f.Lease.Evidence.Id != old.Id && f.Account.HttpCalls == 2,
            "Successful renewal did not expose its actual committed expiry or restarted too soon.");
        f.Stop.Cancel(); await Throws<OperationCanceledException>(() => f.Run!);
        f.Lease.RequireEffectCurrent();
    }
    private static async Task RetrySlots()
    {
        using var f = new Fixture(); await f.Start(); var original = f.Lease.Evidence;
        f.Account.Respond = _ => throw new HttpRequestException(HttpRequestError.ConnectionError, "Fixture unavailable.");
        await f.Fire(0); await Until(() => f.Account.HttpCalls == 2 && f.Renewal!.Snapshot.State == AudioMembershipRenewalState.RetryPending);
        await f.Fire(45_000); await Until(() => f.Account.HttpCalls == 3 && f.Renewal!.Snapshot.State == AudioMembershipRenewalState.RetryPending);
        await f.Fire(35_000);
        await f.Run!.WaitAsync(TimeSpan.FromSeconds(3));
        Require(f.Account.HttpCalls == 4 && ReferenceEquals(original, f.Lease.Evidence) &&
            f.Renewal!.Snapshot is { State: AudioMembershipRenewalState.Unavailable, Failure: AudioMembershipRequestUnavailableException },
            "Temporary failures escaped the retry bound, were hidden or extended the grant.");
        f.Lease.RequireCurrent(); f.Account.Clock.Now = original.Expires;
        await Throws<AudioMembershipException>(() => Call(f.Lease.RequireEffectCurrent));
    }
    private static async Task LateAdmission()
    {
        using var f = new Fixture(); await f.Start(remaining: 60_000);
        f.Account.Respond = _ => throw new HttpRequestException(HttpRequestError.ConnectionError, "Fixture unavailable.");
        await f.Fire(0); await Until(() => f.Account.HttpCalls == 2 && f.Renewal!.Snapshot.State == AudioMembershipRenewalState.RetryPending);
        await f.Fire(20_000); await f.Run!.WaitAsync(TimeSpan.FromSeconds(3));
        Require(f.Account.HttpCalls == 3 && f.Renewal!.Snapshot.State == AudioMembershipRenewalState.Unavailable,
            "Late admission burst through expired attempt slots.");
    }
    private static async Task TimeoutOwnership()
    {
        using var f = new Fixture(); await f.Start(); var original = f.Lease.Evidence;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Account.Respond = async _ => { entered.TrySetResult(); await release.Task; return AudioAccountMembershipTests.Reply(f.Account.Body()); };
        try
        {
            await f.Fire(0); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); await f.Fire(35_000);
            await Until(() => f.Renewal!.Snapshot.State == AudioMembershipRenewalState.Failed);
            await Throws<AudioMembershipException>(() => Call(f.Lease.RequireEffectCurrent));
            Require(!f.Run!.IsCompleted, "Timeout abandoned its noncooperative request.");
            release.TrySetResult();
            var error = await Throws<Exception>(() => f.Run.WaitAsync(TimeSpan.FromSeconds(3)));
            Require(Contains<TimeoutException>(error) && ReferenceEquals(original, f.Lease.Evidence),
                "Timeout lost its cause or allowed late publication.");
        }
        finally { release.TrySetResult(); }
    }
    private static async Task CancellationOwnership()
    {
        using var f = new Fixture(); await f.Start(); var original = f.Lease.Evidence;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Account.Respond = async _ => { entered.TrySetResult(); await release.Task; return AudioAccountMembershipTests.Reply(f.Account.Body()); };
        try
        {
            await f.Fire(0); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); f.Stop.Cancel();
            Require(!f.Run!.IsCompleted, "Cancellation abandoned executing registry work."); f.Lease.RequireCurrent();
            release.TrySetResult(); await Throws<OperationCanceledException>(() => f.Run.WaitAsync(TimeSpan.FromSeconds(3)));
            Require(ReferenceEquals(original, f.Lease.Evidence), "Canceled request published late evidence."); f.Lease.RequireCurrent();
        }
        finally { release.TrySetResult(); }
    }
    private static async Task SynchronousRequest()
    {
        using var f = new Fixture(); using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await f.Start(renew: token => { entered.TrySetResult(); release.Wait(); token.ThrowIfCancellationRequested(); return Task.FromResult(f.Lease); });
        try
        {
            await f.Fire(0); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); await f.Fire(35_000);
            await Until(() => f.Renewal!.Snapshot.State == AudioMembershipRenewalState.Failed);
            Require(!f.Run!.IsCompleted, "Synchronous adapter ownership was abandoned.");
            await Throws<AudioMembershipException>(() => Call(f.Lease.RequireEffectCurrent));
            release.Set(); await Throws<TimeoutException>(() => f.Run.WaitAsync(TimeSpan.FromSeconds(3)));
        }
        finally { release.Set(); }
    }
    private static async Task TimerLoses()
    {
        using var f = new Fixture(); f.Delays.IgnoreAttemptCancellation = true; await f.Start(); var original = f.Lease.Evidence;
        await f.Fire(0); await Until(() => f.Lease.Evidence.Id != original.Id); var timer = await f.Delays.Next();
        Require(timer.Duration == TimeSpan.FromSeconds(35) && f.Lease.Evidence.Id != original.Id,
            "Fixture did not let the request win before its uncancelable timer.");
        f.Account.Clock.Advance(35_000); timer.Release.TrySetResult();
        var next = await f.Delays.Next(); Require(next.Duration > TimeSpan.FromMinutes(50), "The losing timer forced an immediate retry.");
        f.Lease.RequireEffectCurrent(); f.Stop.Cancel(); await Throws<OperationCanceledException>(() => f.Run!);
        f.Lease.RequireEffectCurrent();
    }
    private static async Task InvalidSuccess()
    {
        foreach (bool replacement in new[] { false, true })
        {
            using var f = new Fixture();
            await f.Start(renew: _ => replacement ? f.Account.Lease(f.Inbox) : Task.FromResult(f.Lease));
            await f.Fire(0); await Throws<InvalidDataException>(() => f.Run!.WaitAsync(TimeSpan.FromSeconds(3)));
            Require(f.Renewal!.Snapshot.State == AudioMembershipRenewalState.Failed, "A false renewal success escaped visibly.");
            await Throws<AudioMembershipException>(() => Call(f.Lease.RequireEffectCurrent));
        }
    }
    private static async Task UnexpectedFailure()
    {
        using var f = new Fixture(); var cause = new InvalidDataException("Fixture invalid evidence.");
        await f.Start(renew: _ => throw cause); await f.Fire(0);
        Require(ReferenceEquals(cause, await Throws<InvalidDataException>(() => f.Run!.WaitAsync(TimeSpan.FromSeconds(3)))) &&
            ReferenceEquals(f.Renewal!.Snapshot.Failure, cause), "An unexpected failure was hidden or reclassified.");
        Require(f.Account.HttpCalls == 1, "Unexpected failure issued another request.");
    }
    private static async Task Expiry()
    {
        foreach (bool wall in new[] { true, false })
        {
            using var f = new Fixture(); await f.Start(remaining: 200_000); var expiry = f.Lease.Evidence.Expires;
            var pending = await f.Delays.Next();
            f.Account.Clock.Now = wall ? f.Account.Clock.Now with { WallMilliseconds = expiry.WallMilliseconds } :
                f.Account.Clock.Now with { ContinuousMilliseconds = expiry.ContinuousMilliseconds };
            pending.Release.TrySetResult();
            var error = await Throws<AudioMembershipException>(() => f.Run!.WaitAsync(TimeSpan.FromSeconds(3)));
            Require(error.Reason == AudioMembershipFailure.Expired && f.Account.HttpCalls == 1, "Expired authority began a new request.");
        }
    }
    private static Task Call(Action action) { action(); return Task.CompletedTask; }
    private static void Require(bool value, string message) { if (!value) throw new Exception(message); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    internal static async Task Until(Func<bool> condition)
    { using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3)); while (!condition()) await Task.Delay(1, timeout.Token); }
    private static bool Contains<T>(Exception error) where T : Exception => error is T ||
        error is AggregateException aggregate && aggregate.InnerExceptions.Any(Contains<T>) || error.InnerException is { } inner && Contains<T>(inner);
}
