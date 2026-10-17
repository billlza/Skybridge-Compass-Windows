using System.Net.Http;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>A finite account grant bound to one exact inbox. Playback still requires separate
/// source/output consent. Effect checks never acquire the account, cache or carrier locks.</summary>
internal sealed class AccountAudioMembershipLease
{
    private readonly AccountAudioAuthorization _epoch;
    private readonly ILanAudioStreamInbox _inbox;
    private readonly Func<AudioAuthorizationTime> _clock;
    private readonly AudioDeviceIdentity _local, _peer;
    internal AccountAudioMembershipLease(AudioAccountMembershipEvidence evidence, AccountAudioAuthorization epoch,
        ILanAudioStreamInbox inbox, Func<AudioAuthorizationTime> clock)
    {
        Evidence = evidence; _epoch = epoch; _inbox = inbox; _clock = clock;
        _local = AudioDeviceIdentity.From(inbox.Binding.LocalDeviceId, inbox.Binding.LocalProtocolIdentity);
        _peer = AudioDeviceIdentity.From(inbox.Binding.PeerDeviceId, inbox.Binding.PeerProtocolIdentity);
        RequireCurrent();
    }
    internal AudioAccountMembershipEvidence Evidence { get; }
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
        _epoch.RequireCurrent();
        Evidence.RequireValid(_epoch.Scope, _local, _peer, _clock());
        _epoch.RequireCurrent();
        _inbox.RequireEffectCurrent();
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
    private readonly List<Entry> _entries = [];
    private Request? _pending;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly CancellationToken _lifetimeToken;
    private readonly TaskCompletionSource _closedCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private volatile bool _closed;

    internal AudioAccountMembershipProvider(HttpClient http, Func<AccountAudioAuthorization?> currentEpoch,
        Func<AccountAudioAuthorization, CancellationToken, Task<AccountDeviceAuthentication>> authenticate,
        Func<AudioAuthorizationTime>? clock = null, TimeSpan? queryTimeout = null)
    {
        _currentEpoch = currentEpoch ?? throw new ArgumentNullException(nameof(currentEpoch));
        _authenticate = authenticate ?? throw new ArgumentNullException(nameof(authenticate));
        _clock = clock ?? AudioAuthorizationTime.ReadWindows;
        _lifetimeToken = _lifetime.Token;
        _client = new(http, _clock, queryTimeout);
    }

    internal async Task<AccountAudioMembershipLease> LeaseAsync(ILanAudioStreamInbox inbox,
        CancellationToken cancellationToken, bool refresh = false)
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
        Request request;
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireEpoch(epoch); Prune();
            if (!refresh && _entries.FirstOrDefault(entry => ReferenceEquals(entry.Epoch, epoch) &&
                entry.Evidence.Local == local && entry.Evidence.Peer == peer) is { } cached)
            {
                var cachedLease = new AccountAudioMembershipLease(cached.Evidence, epoch, inbox, _clock);
                cancellationToken.ThrowIfCancellationRequested();
                return cachedLease;
            }
            if (_pending is not null) throw new InvalidOperationException("An audio membership request is already in progress.");
            request = new(epoch, local, peer); _pending = request;
        }
        try
        {
            var authentication = await _authenticate(epoch, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch);
            epoch.RequireAuthentication(authentication); inbox.RequireCurrent();
            AudioRegistryObservation observation;
            try { observation = await _client.QueryAsync(authentication, binding, cancellationToken).ConfigureAwait(false); }
            catch (CurrentPathSignalServerException error) when (IsDeviceDenial(error))
            {
                // An old response can only revoke entries from its captured epoch, never a replacement.
                lock (_gate) RevokeIdentity(epoch, local);
                throw;
            }
            ObserveFresh(epoch, observation);
            // Observe a completed, valid response before rejecting the now-ended requesting stream.
            cancellationToken.ThrowIfCancellationRequested(); RequireEpoch(epoch); inbox.RequireCurrent();
            var evidence = AudioAccountMembershipEvidence.Create(observation, local, peer);
            lock (_gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                RequireEpoch(epoch); inbox.RequireCurrent();
                if (!ReferenceEquals(_pending, request) || request.Contradicted)
                    throw new InvalidOperationException("Device authorization changed during this audio membership request.");
                Prune();
                var previous = _entries.Where(entry => ReferenceEquals(entry.Epoch, epoch) &&
                    entry.Evidence.Local == local && entry.Evidence.Peer == peer).ToArray();
                if (_entries.Count - previous.Length >= Capacity)
                    throw new InvalidOperationException("The audio membership cache is full.");
                var lease = new AccountAudioMembershipLease(evidence, epoch, inbox, _clock);
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var entry in previous) { entry.Evidence.Revoke(); _entries.Remove(entry); }
                _entries.Add(new(epoch, evidence));
                return lease;
            }
        }
        finally
        {
            lock (_gate) { if (ReferenceEquals(_pending, request)) _pending = null; }
            request.Completion.TrySetResult();
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
        _entries.RemoveAll(entry =>
        {
            if (!entry.Epoch.IsCurrent) { entry.Evidence.Revoke(); return true; }
            try { entry.Evidence.RequireValid(entry.Epoch.Scope, entry.Evidence.Local, entry.Evidence.Peer, now); return false; }
            catch (AudioMembershipException error) when (error.Reason is AudioMembershipFailure.Expired or
                AudioMembershipFailure.ClockChanged or AudioMembershipFailure.Revoked) { return true; }
        });
    }
    private static bool IsDeviceDenial(CurrentPathSignalServerException error) => AccountDeviceWire.ErrorCode(error) is
        "device_not_registered" or "device_not_active" or "device_frozen" or "device_revoked";
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
