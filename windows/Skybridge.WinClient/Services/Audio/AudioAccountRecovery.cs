namespace Skybridge.WinClient.Services.Audio;

internal enum AudioAccountRecoveryStatus { NotAttempted, Available, NoSavedGrant, Unsettled, ExpiredOrClockChanged, ContinuityUnavailable, InvalidStoredState }
internal sealed record AudioAccountRecoveryOutcome(AudioAccountRecoveryStatus Status, Exception? Cause = null);
internal sealed record AudioReceiverAccount(AccountAudioAuthorization Authorization, string DisplayName, string NebulaId, long? OfflineExpiresAt);

internal interface IAudioAccountRecoveryStore
{
    ValueTask<AudioStoredMembership> RestoreMembershipAsync(AccountAudioAuthorization epoch, AudioDeviceIdentity local,
        AudioDeviceIdentity peer, CancellationToken cancellationToken);
}
internal sealed record AudioStoredMembership(AudioAccountMembershipEvidence? Evidence, AudioAccountRecoveryStatus Status, Exception? Cause = null);

// A bounded set captured from the protected canonical record. Candidates are
// historical metadata, not proof of a new connection's identities. Only the
// account owner's RestoreMembershipAsync can bind one to an actual MAIN inbox.
internal sealed class AudioAccountRecoverySnapshot
{
    private readonly Candidate[] _candidates;
    private readonly Func<AudioAuthorizationTime> _clock;
    internal AudioAccountRecoverySnapshot(Guid loginId, AudioAccountScope scope, string displayName, string nebulaId,
        IEnumerable<AudioMembershipCheckpoint> candidates, Func<AudioAuthorizationTime> clock)
    {
        ArgumentNullException.ThrowIfNull(scope); scope.Validate();
        ArgumentNullException.ThrowIfNull(candidates); ArgumentNullException.ThrowIfNull(clock);
        LoginId = loginId; Scope = scope; DisplayName = displayName; NebulaId = nebulaId; _clock = clock;
        _candidates = candidates.Select(value => new Candidate(value)).ToArray();
        if (loginId == Guid.Empty || _candidates.Length is < 1 or > AudioAccountJournalState.Capacity)
            throw new InvalidDataException("Invalid saved audio recovery set.");
        if (_candidates.Select(c => c.Value.EvidenceId).Distinct().Count() != _candidates.Length ||
            _candidates.Select(c => (c.Value.Local, c.Value.Peer)).Distinct().Count() != _candidates.Length)
            throw new InvalidDataException("Duplicate saved audio recovery candidate.");
        foreach (var candidate in _candidates)
        {
            candidate.Value.Validate();
            if (candidate.Value.LoginId != loginId || candidate.Value.Scope != scope)
                throw new InvalidDataException("Saved audio recovery set changed its account owner.");
        }
    }
    internal Guid LoginId { get; }
    internal AudioAccountScope Scope { get; }
    internal string DisplayName { get; }
    internal string NebulaId { get; }
    internal bool HasCurrentCandidate => LatestExpiry is not null;
    internal long? LatestExpiry
    {
        get
        {
            var now = _clock(); long? latest = null;
            foreach (var candidate in _candidates)
                if (candidate.IsCurrent(now)) latest = Math.Max(latest ?? 0, candidate.Value.Expires.WallMilliseconds);
            return latest;
        }
    }
    internal AudioMembershipCheckpoint? Find(AudioDeviceIdentity local, AudioDeviceIdentity peer)
    {
        var now = _clock();
        return _candidates.FirstOrDefault(c => c.Value.Local.Matches(local) && c.Value.Peer.Matches(peer) && c.IsCurrent(now))?.Value;
    }
    // Discovery/SOA uses a canonical routing ID. This only decides whether to
    // attempt MAIN; it cannot restore membership. Find still requires the exact
    // device ID declared inside the authenticated session, including its spelling.
    internal bool HasProtocolCandidate(AudioDeviceIdentity local, AudioDeviceIdentity discoveredPeer)
    {
        var now = _clock();
        string routeId = RemoteControlHandshakeBinding.CanonicalDeviceId(discoveredPeer.DeviceId);
        return _candidates.Any(c => c.Value.Local.Matches(local) &&
            RemoteControlHandshakeBinding.CanonicalDeviceId(c.Value.Peer.DeviceId) == routeId &&
            c.Value.Peer.Algorithm == discoveredPeer.Algorithm && c.Value.Peer.Fingerprint == discoveredPeer.Fingerprint && c.IsCurrent(now));
    }
    internal void RequireLocalIdentity(AudioDeviceIdentity local)
    {
        var now = _clock();
        if (!_candidates.Any(c => c.Value.Local.Matches(local) && c.IsCurrent(now)))
            throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
    }
    internal static bool WithinBounds(AudioMembershipCheckpoint checkpoint, AudioAuthorizationTime now) =>
        now.WallMilliseconds >= checkpoint.Issued.WallMilliseconds && now.ContinuousMilliseconds >= checkpoint.Issued.ContinuousMilliseconds &&
        now.WallMilliseconds < checkpoint.Expires.WallMilliseconds && now.ContinuousMilliseconds < checkpoint.Expires.ContinuousMilliseconds;
    private sealed class Candidate(AudioMembershipCheckpoint value)
    {
        private int _retired;
        internal AudioMembershipCheckpoint Value { get; } = value;
        internal bool IsCurrent(AudioAuthorizationTime now)
        {
            if (!WithinBounds(Value, now)) Interlocked.Exchange(ref _retired, 1);
            return Volatile.Read(ref _retired) == 0;
        }
    }
}
