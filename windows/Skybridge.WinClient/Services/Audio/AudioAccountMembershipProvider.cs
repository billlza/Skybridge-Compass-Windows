using System.Net.Http;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>A finite account grant bound to one exact inbox. Playback still requires separate
/// source/output consent. Effect checks use only this lease's bounded gate, never
/// the account owner's mutation gate, cache gate or carrier locks.</summary>
internal sealed class AccountAudioMembershipLease
{
    private readonly object _gate = new();
    private readonly AccountAudioAuthorization _epoch;
    private readonly ILanAudioStreamInbox _inbox;
    private readonly Func<AudioAuthorizationTime> _clock;
    private readonly AudioDeviceIdentity _local, _peer;
    private AudioAccountMembershipEvidence _evidence;
    private bool _revoked;
    private Exception? _revocationCause;
    internal AccountAudioMembershipLease(AudioAccountMembershipEvidence evidence, AccountAudioAuthorization epoch,
        ILanAudioStreamInbox inbox, Func<AudioAuthorizationTime> clock)
    {
        _evidence = evidence; _epoch = epoch; _inbox = inbox; _clock = clock;
        _local = AudioDeviceIdentity.From(inbox.Binding.LocalDeviceId, inbox.Binding.LocalProtocolIdentity);
        _peer = AudioDeviceIdentity.From(inbox.Binding.PeerDeviceId, inbox.Binding.PeerProtocolIdentity);
        RequireCurrent();
    }
    internal AudioAccountMembershipEvidence Evidence { get { lock (_gate) return _evidence; } }
    internal Guid StreamId => _inbox.StreamId;
    internal string SessionId => _inbox.Binding.SessionId;
    internal void RequireInbox(ILanAudioStreamInbox inbox)
    {
        if (!ReferenceEquals(_inbox, inbox))
            throw new InvalidDataException("Audio membership belongs to a different stream owner.");
    }
    internal void RequireCurrent()
    { _inbox.RequireCurrent(); RequireEffectCurrent(); _inbox.RequireCurrent(); }
    internal void RequireEffectCurrent()
    {
        _inbox.RequireEffectCurrent();
        lock (_gate) RequireAccountEffect();
        _inbox.RequireEffectCurrent();
    }
    private void RequireAccountEffect()
    {
        if (_revoked) throw new AudioMembershipException(AudioMembershipFailure.Revoked, _revocationCause);
        _epoch.RequireCurrent();
        _evidence.RequireValid(_epoch.Scope, _local, _peer, _clock());
        _epoch.RequireCurrent();
    }
    internal void Revoke(Exception? cause = null)
    {
        lock (_gate)
        {
            if (_revoked) return;
            // The effect boundary observes the first terminal cause and its
            // revocation together. A later cleanup failure cannot replace it.
            _revocationCause = cause;
            _revoked = true;
        }
    }
    internal AudioAccountMembershipEvidence RequireContinuation(AccountAudioAuthorization epoch, ILanAudioStreamInbox inbox)
    {
        RequireInbox(inbox);
        if (!ReferenceEquals(_epoch, epoch)) throw new AudioMembershipException(AudioMembershipFailure.ScopeChanged);
        RequireCurrent();
        lock (_gate) { RequireAccountEffect(); return _evidence; }
    }
    // Called only after a fresh provider observation on the original request.
    // No carrier/cache lock is acquired while holding this lease's effect gate.
    internal void ContinueWith(AudioAccountMembershipEvidence expected, AudioAccountMembershipEvidence replacement,
        CancellationToken cancellationToken)
    {
        _inbox.RequireCurrent();
        lock (_gate)
        {
            RequireAccountEffect();
            if (!ReferenceEquals(_evidence, expected) || replacement.Id == expected.Id ||
                replacement.Issued.WallMilliseconds <= expected.Issued.WallMilliseconds ||
                replacement.Issued.ContinuousMilliseconds <= expected.Issued.ContinuousMilliseconds ||
                replacement.Expires.WallMilliseconds <= expected.Expires.WallMilliseconds ||
                replacement.Expires.ContinuousMilliseconds <= expected.Expires.ContinuousMilliseconds)
                throw new InvalidOperationException("Audio continuation requires fresh evidence for its exact predecessor.");
            var now = _clock();
            expected.RequireValid(_epoch.Scope, _local, _peer, now);
            replacement.RequireValid(_epoch.Scope, _local, _peer, now);
            _inbox.RequireEffectCurrent(); _epoch.RequireCurrent();
            cancellationToken.ThrowIfCancellationRequested();
            _evidence = replacement;
            expected.Revoke(); // Other consumers remain finite; only this one was explicitly continued.
        }
    }
}

/// <summary>Process-local evidence cache. Only a fresh authenticated read-only GET issues evidence;
/// observations/removals only revoke. Credential callbacks must use their account owner's context.</summary>
internal sealed class AudioAccountMembershipProvider : IAsyncDisposable
{
    internal const int Capacity = 32;
    private readonly object _gate = new();
    private readonly Func<AccountAudioAuthorization?> _currentEpoch;
    private readonly Func<AccountAudioAuthorization, CancellationToken, Task<AccountDeviceAuthentication>> _authenticate;
    private readonly Func<AudioAuthorizationTime> _clock;
    private readonly AudioAccountMembershipClient _client;
    private readonly IAudioLogonContinuity _continuity;
    private readonly List<Entry> _entries = [];
    // Only the bounded startup snapshot is restorable. Keep its runtime evidence
    // objects, including terminal failures, so cache pruning cannot revive them.
    private readonly Dictionary<Guid, Entry> _recovered = [];
    private Request? _pending;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly CancellationToken _lifetimeToken;
    private readonly TaskCompletionSource _closedCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private volatile bool _closed;

    internal AudioAccountMembershipProvider(HttpClient http, Func<AccountAudioAuthorization?> currentEpoch,
        Func<AccountAudioAuthorization, CancellationToken, Task<AccountDeviceAuthentication>> authenticate,
        Func<AudioAuthorizationTime>? clock = null, TimeSpan? queryTimeout = null, IAudioLogonContinuity? continuity = null)
    {
        _currentEpoch = currentEpoch ?? throw new ArgumentNullException(nameof(currentEpoch));
        _authenticate = authenticate ?? throw new ArgumentNullException(nameof(authenticate));
        _clock = clock ?? AudioAuthorizationTime.ReadWindows;
        _lifetimeToken = _lifetime.Token;
        _client = new(http, _clock, queryTimeout);
        _continuity = continuity ?? WindowsAudioLogonContinuity.Instance;
    }

    internal Task<AccountAudioMembershipLease> LeaseAsync(ILanAudioStreamInbox inbox,
        CancellationToken cancellationToken, bool refresh = false) =>
        AcquireAsync(inbox, cancellationToken, refresh, continuing: null);

    internal Task<AccountAudioMembershipLease> RenewAsync(ILanAudioStreamInbox inbox,
        AccountAudioMembershipLease continuing, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(continuing);
        return AcquireAsync(inbox, cancellationToken, refresh: true, continuing: continuing);
    }

    private async Task<AccountAudioMembershipLease> AcquireAsync(ILanAudioStreamInbox inbox,
        CancellationToken cancellationToken, bool refresh, AccountAudioMembershipLease? continuing)
    {
        ArgumentNullException.ThrowIfNull(inbox);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetimeToken);
        cancellationToken = lifetime.Token;
        cancellationToken.ThrowIfCancellationRequested();
        var epoch = _currentEpoch() ?? throw new InvalidOperationException("No current authenticated audio account is available.");
        RequireEpoch(epoch); inbox.RequireCurrent();
        var binding = inbox.Binding;
        var local = AudioDeviceIdentity.From(binding.LocalDeviceId, binding.LocalProtocolIdentity);
        var peer = AudioDeviceIdentity.From(binding.PeerDeviceId, binding.PeerProtocolIdentity);
        var predecessor = continuing?.RequireContinuation(epoch, inbox);
        Request request;
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireEpoch(epoch); Prune();
            if (continuing is not null) RequireContinuation();
            if (!refresh && _entries.FirstOrDefault(entry => ReferenceEquals(entry.Epoch, epoch) &&
                entry.Evidence.Local == local && entry.Evidence.Peer == peer) is { } cached)
            {
                var cachedLease = new AccountAudioMembershipLease(cached.Evidence, epoch, inbox, _clock);
                cancellationToken.ThrowIfCancellationRequested();
                return cachedLease;
            }
            if (_pending is not null) throw new AudioMembershipRequestBusyException();
            request = new(epoch, local, peer); _pending = request;
        }
        try
        {
            var evidence = !refresh ? await RestoreSavedMembershipAsync(request, cancellationToken).ConfigureAwait(false) : null;
            if (evidence is null)
            {
                var authentication = await _authenticate(epoch, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch);
                epoch.RequireAuthentication(authentication); inbox.RequireCurrent();
                try { evidence = await QueryMembershipAsync(request, authentication, inbox, cancellationToken).ConfigureAwait(false); }
                catch (Exception error) when (continuing is not null && IsTemporaryRequest(error))
                {
                    cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch);
                    continuing.RequireContinuation(epoch, inbox);
                    throw new AudioMembershipRequestUnavailableException(error);
                }
            }
            lock (_gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                RequireEpoch(epoch); inbox.RequireCurrent();
                if (!ReferenceEquals(_pending, request)) throw new InvalidOperationException("Audio membership request ownership changed.");
                if (request.Contradicted) throw new AudioMembershipSupersededException();
                Prune();
                if (continuing is not null) RequireContinuation();
                var previous = _entries.Where(entry => ReferenceEquals(entry.Epoch, epoch) &&
                    entry.Evidence.Local == local && entry.Evidence.Peer == peer).ToArray();
                if (_entries.Count - previous.Length >= Capacity)
                    throw new InvalidOperationException("The audio membership cache is full.");
                var next = new Entry(epoch, evidence);
                var lease = continuing ?? new AccountAudioMembershipLease(evidence, epoch, inbox, _clock);
                cancellationToken.ThrowIfCancellationRequested();
                if (continuing is not null)
                    continuing.ContinueWith(predecessor ?? throw new InvalidOperationException("Missing audio predecessor."), evidence, cancellationToken);
                foreach (var entry in previous) { entry.Evidence.Revoke(); _entries.Remove(entry); }
                _entries.Add(next);
                return lease;
            }
        }
        finally
        {
            lock (_gate) { if (ReferenceEquals(_pending, request)) _pending = null; }
            request.Completion.TrySetResult();
        }
        void RequireContinuation()
        {
            if (continuing is null || predecessor is null ||
                !ReferenceEquals(continuing.RequireContinuation(epoch, inbox), predecessor) ||
                !_entries.Any(entry => ReferenceEquals(entry.Epoch, epoch) && ReferenceEquals(entry.Evidence, predecessor)))
                throw new InvalidOperationException("The original audio authorization can no longer be continued.");
        }
    }

    private async Task<AudioAccountMembershipEvidence?> RestoreSavedMembershipAsync(Request request, CancellationToken token)
    {
        var epoch = request.Epoch;
        if (epoch.Recovery is null) return null; // Ordinary online publication has no startup recovery set.
        if (epoch.Observations is not IAudioAccountRecoveryStore recovery)
            throw new InvalidOperationException("Saved audio authorization requires its canonical account owner.");
        var stored = await recovery.RestoreMembershipAsync(epoch, request.Local, request.Peer, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested(); RequireEpoch(epoch);
        if (stored.Evidence is not { } evidence)
        {
            if (stored.Status is not (AudioAccountRecoveryStatus.NoSavedGrant or AudioAccountRecoveryStatus.Unsettled or
                AudioAccountRecoveryStatus.ExpiredOrClockChanged or AudioAccountRecoveryStatus.ContinuityUnavailable))
                throw new InvalidDataException("Saved audio lookup has no explicit outcome.");
            if (epoch.IsOffline) throw new AudioMembershipException(AudioMembershipFailure.Revoked, stored.Cause);
            return null; // A verified online account must perform a new GET; failed recovery never issues a grant.
        }
        lock (_gate)
        {
            RequireEpoch(epoch); Prune();
            if (_recovered.TryGetValue(evidence.Id, out var existing))
            {
                if (!ReferenceEquals(existing.Epoch, epoch)) throw new InvalidDataException("Saved evidence belongs to another publication.");
                evidence = existing.Evidence;
            }
            else
            {
                if (_recovered.Count >= Capacity) throw new InvalidOperationException("The saved audio recovery set is full.");
                _recovered.Add(evidence.Id, new(epoch, evidence));
            }
        }
        try { evidence.RequireValid(epoch.Scope, request.Local, request.Peer, _clock()); }
        catch (AudioMembershipException error) when (!epoch.IsOffline && error.Reason is
            AudioMembershipFailure.Revoked or AudioMembershipFailure.Expired or AudioMembershipFailure.ClockChanged)
        { return null; }
        return evidence;
    }

    private async Task<AudioAccountMembershipEvidence> QueryMembershipAsync(Request request,
        AccountDeviceAuthentication authentication, ILanAudioStreamInbox inbox, CancellationToken cancellationToken)
    {
        var epoch = request.Epoch;
        var store = epoch.Observations;
        AudioJournalTicket? ticket;
        try
        {
            ticket = store is null ? null : await store.BeginAsync(epoch, request.Local, AccountDeviceRegistryRequest.List,
                null, cancellationToken, request.Peer).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) { throw new AudioMembershipJournalException("preparation", error); }

        AudioRegistryObservation? observation = null;
        Exception? failure = null;
        bool settlementAttempted = false;
        bool callerRejected = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch); inbox.RequireCurrent();
            observation = await _client.QueryAsync(authentication, inbox.Binding, cancellationToken).ConfigureAwait(false);
            // Completed negatives affect running consumers before any disk work,
            // including when the requesting inbox has meanwhile ended.
            ObserveFresh(epoch, observation);
            cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch); inbox.RequireCurrent();
            var evidence = AudioAccountMembershipEvidence.Create(observation, request.Local, request.Peer);
            lock (_gate)
            {
                RequireEpoch(epoch);
                if (!ReferenceEquals(_pending, request)) throw new InvalidOperationException("Audio membership request ownership changed.");
                if (request.Contradicted) throw new AudioMembershipSupersededException();
                Prune();
                if (_entries.Count(entry => !ReferenceEquals(entry.Epoch, epoch) ||
                    entry.Evidence.Local != request.Local || entry.Evidence.Peer != request.Peer) >= Capacity)
                    throw new InvalidOperationException("The audio membership cache is full.");
            }
            if (store is not null && ticket is not null)
            {
                // DPAPI/sealing and canonical-file I/O never run under the
                // provider or playback effect lock, nor inline on the UI thread.
                var checkpoint = await Task.Run(() => AudioMembershipCheckpoint.Capture(ticket.LoginId, evidence,
                    _clock, _continuity), cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch); inbox.RequireCurrent();
                settlementAttempted = true;
                AudioJournalCompletion completed;
                try { completed = await store.CompleteAsync(ticket, new(observation, null, false, checkpoint), null).ConfigureAwait(false); }
                catch (Exception error) { throw new AudioMembershipJournalException("completion", error); }
                if (completed != AudioJournalCompletion.Committed)
                    throw new InvalidOperationException($"Audio membership journal rejected its owner: {completed}.");
            }
            // The caller rechecks its exact pending owner and inbox under the
            // cache gate before publishing this evidence to any playback lease.
            evidence.RequireValid(epoch.Scope, request.Local, request.Peer, _clock());
            return evidence;
        }
        catch (Exception error)
        {
            failure = error;
            callerRejected = error is CurrentPathSignalServerException denied && IsDeviceDenial(denied);
            if (callerRejected) lock (_gate) RevokeIdentity(epoch, request.Local);
            throw;
        }
        finally
        {
            if (store is not null && ticket is not null && !settlementAttempted)
            {
                // Cancellation and negative responses still settle the exact
                // prepared owner. A failed/uncertain commit is never retried.
                try { await store.CompleteAsync(ticket, new(observation, null, callerRejected), failure).ConfigureAwait(false); }
                catch (Exception completionFailure)
                {
                    var context = new AudioMembershipJournalException("completion", completionFailure);
                    if (failure is null) throw context;
                    throw new AggregateException("Audio membership query and journal completion failed.", failure, context);
                }
            }
        }
    }

    internal bool ObserveFresh(AccountAudioAuthorization epoch, AudioRegistryObservation observation)
    {
        lock (_gate)
        {
            if (!IsCurrentEpoch(epoch)) return false;
            if (observation.Scope != epoch.Scope) throw new AudioMembershipException(AudioMembershipFailure.ScopeChanged);
            observation.RequireFreshAt(_clock());
            foreach (var entry in _entries.Where(entry => ReferenceEquals(entry.Epoch, epoch)))
                if (observation.Contradicts(entry.Evidence.Local, entry.Evidence.Peer)) entry.Evidence.Revoke();
            if (_pending is { } request && ReferenceEquals(request.Epoch, epoch) &&
                observation.Contradicts(request.Local, request.Peer)) request.Contradicted = true;
            return true;
        }
    }

    internal bool ObserveRegistryResponse(AccountAudioAuthorization epoch, AccountDeviceAuthentication authentication,
        AudioDeviceIdentity caller, AccountDeviceRosterSnapshot snapshot, AudioAuthorizationTime started, AudioAuthorizationTime received)
    {
        lock (_gate)
        {
            if (!IsCurrentEpoch(epoch)) return false;
            try
            {
                // Account retirement uses a different gate. Bind immutable scope here; do not
                // turn a concurrent same-account relogin into a device-page refresh failure.
                if (epoch.Scope != AudioAccountScope.From(authentication))
                    throw new AudioMembershipException(AudioMembershipFailure.ScopeChanged);
                return ObserveFresh(epoch, AudioRegistryObservation.FromResponse(authentication, caller, snapshot, started, received));
            }
            catch (AudioMembershipException) when (!IsCurrentEpoch(epoch)) { return false; }
        }
    }

    internal bool ObserveCallerRejection(AccountAudioAuthorization epoch, AudioDeviceIdentity caller, CurrentPathSignalServerException error)
    {
        lock (_gate)
        {
            if (!IsCurrentEpoch(epoch) || !IsDeviceDenial(error)) return false;
            RevokeIdentity(epoch, caller);
            return true;
        }
    }

    // Call only with a confirmed exact removal identity, or an authenticated device-denial result.
    internal bool Removed(AccountAudioAuthorization epoch, AccountDeviceEntry target)
    {
        lock (_gate)
        {
            if (!IsCurrentEpoch(epoch)) return false;
            foreach (var entry in _entries.Where(entry => ReferenceEquals(entry.Epoch, epoch)))
                if (entry.Evidence.Local.Matches(target) || entry.Evidence.Peer.Matches(target)) entry.Evidence.Revoke();
            if (_pending is { } request && ReferenceEquals(request.Epoch, epoch) &&
                (request.Local.Matches(target) || request.Peer.Matches(target))) request.Contradicted = true;
            return true;
        }
    }

    private void RevokeIdentity(AccountAudioAuthorization epoch, AudioDeviceIdentity identity)
    {
        foreach (var entry in _entries.Where(entry => ReferenceEquals(entry.Epoch, epoch)))
            if (entry.Evidence.Local == identity || entry.Evidence.Peer == identity) entry.Evidence.Revoke();
        if (_pending is { } request && ReferenceEquals(request.Epoch, epoch) &&
            (request.Local == identity || request.Peer == identity)) request.Contradicted = true;
    }
    private void RequireEpoch(AccountAudioAuthorization expected)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        expected.RequireCurrent();
        if (!ReferenceEquals(_currentEpoch(), expected))
            throw new InvalidOperationException("The audio membership account publication changed.");
        expected.RequireCurrent();
    }
    private bool IsCurrentEpoch(AccountAudioAuthorization expected) => !_closed && expected.IsCurrent && ReferenceEquals(_currentEpoch(), expected);

    public async ValueTask DisposeAsync()
    {
        Task? draining = null;
        lock (_gate)
        {
            if (!_closed)
            {
                _closed = true;
                foreach (var entry in _entries) entry.Evidence.Revoke();
                _entries.Clear();
                foreach (var entry in _recovered.Values) entry.Evidence.Revoke();
                _recovered.Clear();
                if (_pending is { } request) request.Contradicted = true;
                draining = _pending?.Completion.Task ?? Task.CompletedTask;
            }
        }
        if (draining is null) { await _closedCompletion.Task.ConfigureAwait(false); return; }
        try
        {
            try { _lifetime.Cancel(); }
            finally { await draining.ConfigureAwait(false); _lifetime.Dispose(); }
            _closedCompletion.TrySetResult();
        }
        catch (Exception failure) { _closedCompletion.TrySetException(failure); }
        await _closedCompletion.Task.ConfigureAwait(false);
    }
    private void Prune()
    {
        var now = _clock();
        var epoch = _currentEpoch();
        foreach (var key in _recovered.Where(item => !ReferenceEquals(item.Value.Epoch, epoch) || !item.Value.Epoch.IsCurrent).Select(item => item.Key).ToArray())
        { _recovered[key].Evidence.Revoke(); _recovered.Remove(key); }
        _entries.RemoveAll(entry =>
        {
            if (!entry.Epoch.IsCurrent) { entry.Evidence.Revoke(); return true; }
            try { entry.Evidence.RequireValid(entry.Epoch.Scope, entry.Evidence.Local, entry.Evidence.Peer, now); return false; }
            catch (AudioMembershipException error) when (error.Reason is AudioMembershipFailure.Expired or
                AudioMembershipFailure.ClockChanged or AudioMembershipFailure.Revoked) { return true; }
        });
    }
    internal static bool IsDeviceDenial(CurrentPathSignalServerException error) => AccountDeviceWire.ErrorCode(error) is
        "device_not_registered" or "device_not_active" or "device_frozen" or "device_revoked";
    private static bool IsTemporaryRequest(Exception error) => error switch
    {
        AudioMembershipQueryTimeoutException => true,
        HttpRequestException request => AudioMembershipRequestFailure.IsTemporary(request),
        HttpIOException response => AudioMembershipRequestFailure.IsTemporary(response),
        CurrentPathSignalServerException response => AccountDeviceWire.ErrorCode(response) != "current_identity_mismatch" &&
            !IsDeviceDenial(response) && AudioMembershipRequestFailure.IsTemporary(response.StatusCode),
        _ => false
    };
    private sealed record Entry(AccountAudioAuthorization Epoch, AudioAccountMembershipEvidence Evidence);
    private sealed class Request(AccountAudioAuthorization epoch, AudioDeviceIdentity local, AudioDeviceIdentity peer)
    {
        internal AccountAudioAuthorization Epoch { get; } = epoch;
        internal AudioDeviceIdentity Local { get; } = local;
        internal AudioDeviceIdentity Peer { get; } = peer;
        internal bool Contradicted;
        internal TaskCompletionSource Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}

internal sealed class AudioMembershipJournalException(string stage, Exception cause)
    : IOException($"Audio membership journal {stage} failed.", cause)
{
    internal string Stage { get; } = stage;
}

// A confirmed concurrent observation already retired this pending pair. This
// is terminal for the request, but cannot revoke unrelated pairs as an outage.
internal sealed class AudioMembershipSupersededException()
    : InvalidOperationException("A confirmed device observation superseded this audio membership request.");
