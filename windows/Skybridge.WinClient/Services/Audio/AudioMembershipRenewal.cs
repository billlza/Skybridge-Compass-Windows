using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioMembershipRenewalState { Waiting, Checking, RetryPending, Unavailable, Failed }
internal sealed record AudioMembershipRenewalSnapshot(AudioMembershipRenewalState State,
    AudioAccountMembershipEvidence Evidence, Exception? Failure = null);

/// <summary>Owned by one receive session. Only its original lease can be continued;
/// no source, connection, output, account or playback consent is selected here.</summary>
internal sealed class AudioMembershipRenewal
{
    private readonly AccountAudioMembershipLease _lease;
    private readonly Func<CancellationToken, Task<AccountAudioMembershipLease>> _renew;
    private readonly Func<AudioAuthorizationTime> _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private AudioMembershipRenewalSnapshot _snapshot;
    private int _started;

    internal AudioMembershipRenewal(AccountAudioMembershipLease lease,
        Func<CancellationToken, Task<AccountAudioMembershipLease>> renew,
        Func<AudioAuthorizationTime>? clock = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _lease = lease ?? throw new ArgumentNullException(nameof(lease));
        _renew = renew ?? throw new ArgumentNullException(nameof(renew)); _clock = clock ?? AudioAuthorizationTime.ReadWindows;
        _delay = delay ?? ((duration, token) => Task.Delay(duration, token));
        _snapshot = new(AudioMembershipRenewalState.Waiting, lease.Evidence);
    }
    internal AudioMembershipRenewalSnapshot Snapshot => Volatile.Read(ref _snapshot);

    internal async Task RunAsync(CancellationToken token)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
            throw new InvalidOperationException("Audio renewal is single-use.");
        try
        {
            while (true)
            {
                var previous = Checkpoint(token); Publish(AudioMembershipRenewalState.Waiting);
                int attempts = 0; bool renewed = false; Exception? lastTemporary = null;
                foreach (long lead in new long[] { 120_000, 75_000, 40_000 })
                {
                    RequirePredecessor(previous, token);
                    long beforeWait = Remaining(previous);
                    if (attempts > 0 && beforeWait < lead) continue; // No burst for missed retry slots.
                    await _delay(TimeSpan.FromMilliseconds(Math.Max(0, beforeWait - lead)), token).ConfigureAwait(false);
                    RequirePredecessor(previous, token);
                    Publish(AudioMembershipRenewalState.Checking);
                    long budget = Math.Min(35_000, Remaining(previous) - 1);
                    if (budget <= 0) break;
                    attempts++;
                    try { await AttemptAsync(TimeSpan.FromMilliseconds(budget), token).ConfigureAwait(false); }
                    catch (Exception error) when (error is AudioMembershipRequestUnavailableException or AudioMembershipRequestBusyException)
                    {
                        RequirePredecessor(previous, token);
                        lastTemporary = error; Publish(AudioMembershipRenewalState.RetryPending, error);
                        continue;
                    }
                    var fresh = Checkpoint(token);
                    if (fresh.Id == previous.Id || fresh.Scope != previous.Scope || fresh.Local != previous.Local || fresh.Peer != previous.Peer ||
                        fresh.Issued.WallMilliseconds <= previous.Issued.WallMilliseconds || fresh.Issued.ContinuousMilliseconds <= previous.Issued.ContinuousMilliseconds ||
                        fresh.Expires.WallMilliseconds <= previous.Expires.WallMilliseconds || fresh.Expires.ContinuousMilliseconds <= previous.Expires.ContinuousMilliseconds)
                        throw new InvalidDataException("Audio renewal did not commit fresh evidence for the original consumer.");
                    renewed = true; break;
                }
                if (!renewed)
                {
                    Publish(AudioMembershipRenewalState.Unavailable, lastTemporary);
                    return; // Every effect still enforces the unchanged finite expiry.
                }
            }
        }
        catch (OperationCanceledException error) when (token.IsCancellationRequested && error.InnerException is null)
        { throw new OperationCanceledException(token); }
        catch (Exception failure)
        {
            Publish(AudioMembershipRenewalState.Failed, failure); _lease.Revoke(); throw;
        }
    }

    private AudioAccountMembershipEvidence Checkpoint(CancellationToken token)
    { token.ThrowIfCancellationRequested(); _lease.RequireCurrent(); return _lease.Evidence; }
    private void RequirePredecessor(AudioAccountMembershipEvidence expected, CancellationToken token)
    {
        if (!ReferenceEquals(expected, Checkpoint(token)))
            throw new InvalidOperationException("The audio renewal predecessor changed.");
    }
    private long Remaining(AudioAccountMembershipEvidence evidence)
    {
        var now = _clock(); evidence.RequireValid(evidence.Scope, evidence.Local, evidence.Peer, now);
        return Math.Min(evidence.Expires.WallMilliseconds - now.WallMilliseconds,
            evidence.Expires.ContinuousMilliseconds - now.ContinuousMilliseconds);
    }
    private void Publish(AudioMembershipRenewalState state, Exception? failure = null) =>
        Volatile.Write(ref _snapshot, new(state, _lease.Evidence, failure));

    private async Task AttemptAsync(TimeSpan budget, CancellationToken token)
    {
        using var requestScope = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var timerScope = CancellationTokenSource.CreateLinkedTokenSource(token);
        var outcome = new TaskCompletionSource<Exception?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var late = new ConcurrentQueue<Exception>();
        var gate = new object(); bool finished = false;
        using var cancellation = token.Register(() => Finish(new OperationCanceledException(token), revoke: false));
        // Arm the timer before invoking an adapter that may do synchronous work
        // before returning its Task. A deadline already won must not start I/O.
        var timer = Deadline(); var request = outcome.Task.IsCompleted ? Task.CompletedTask : Request();
        Exception? failure = await outcome.Task.ConfigureAwait(false);
        Cancel(requestScope); Cancel(timerScope);
        await Task.WhenAll(request, timer).ConfigureAwait(false); // Retain ownership of noncooperative requests.
        if (!late.IsEmpty)
        {
            var failures = late.ToList(); if (failure is not null) failures.Insert(0, failure);
            throw new AggregateException("Audio renewal failed while draining its request owners.", failures);
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        token.ThrowIfCancellationRequested();

        bool Finish(Exception? error, bool revoke)
        {
            lock (gate)
            {
                if (finished) return false;
                finished = true;
                if (revoke && error is not null)
                {
                    // Publish the actual deadline cause before render effects observe revocation.
                    Publish(AudioMembershipRenewalState.Failed, error); _lease.Revoke();
                }
                outcome.TrySetResult(error); return true;
            }
        }
        async Task Request()
        {
            try
            {
                requestScope.Token.ThrowIfCancellationRequested();
                var continued = await _renew(requestScope.Token).ConfigureAwait(false);
                requestScope.Token.ThrowIfCancellationRequested();
                if (!ReferenceEquals(continued, _lease)) throw new InvalidDataException("Audio renewal returned a different consumer.");
                Finish(null, revoke: false);
            }
            catch (Exception error)
            {
                if (!Finish(error, revoke: false) && !ExpectedCancellation(error, requestScope)) late.Enqueue(error);
            }
        }
        async Task Deadline()
        {
            try
            {
                await _delay(budget, timerScope.Token).ConfigureAwait(false);
                timerScope.Token.ThrowIfCancellationRequested();
                Finish(new TimeoutException("Audio membership renewal exceeded its finite attempt deadline."), revoke: true);
            }
            catch (Exception error)
            {
                if (!ExpectedCancellation(error, timerScope) && !Finish(error, revoke: true)) late.Enqueue(error);
            }
        }
        void Cancel(CancellationTokenSource source) { try { source.Cancel(); } catch (Exception error) { late.Enqueue(error); } }
        static bool ExpectedCancellation(Exception error, CancellationTokenSource source) =>
            error is OperationCanceledException { InnerException: null } && source.IsCancellationRequested;
    }
}
