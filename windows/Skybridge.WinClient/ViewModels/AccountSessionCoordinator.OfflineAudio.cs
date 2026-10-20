using System.ComponentModel;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

namespace Skybridge.WinClient.ViewModels;

public sealed partial class AccountSessionCoordinator : IAudioAccountRecoveryStore
{
    private readonly Func<AudioAuthorizationTime> _audioClock = AudioAuthorizationTime.ReadWindows;
    private readonly IAudioLogonContinuity _audioContinuity = WindowsAudioLogonContinuity.Instance;

    internal AccountSessionCoordinator(ISupabaseAuthClient auth, ISessionStore store,
        Func<AudioAuthorizationTime> clock, IAudioLogonContinuity continuity) : this(auth, store)
    { _audioClock = clock; _audioContinuity = continuity; }

    internal AudioReceiverAccount? ReadAudioReceiverAccount()
    {
        var epoch = ReadAudioAuthorization();
        if (epoch is null || !epoch.IsCurrent) return null;
        if (IsSignedIn) return new(epoch, DisplayName, NebulaId, null);
        return epoch.IsOffline && epoch.Recovery is { } saved && saved.LatestExpiry is { } expiry
            ? new(epoch, saved.DisplayName, saved.NebulaId, expiry) : null;
    }

    // The owner already holds its account mutation gate and has durably settled
    // an allowlisted temporary authentication failure. This publishes only an
    // audio capability; ordinary signed-in account operations remain unavailable.
    private async Task<AudioAccountRecoveryOutcome> RestoreOfflineAudioAsync()
    {
        var recovered = await Task.Run<(AudioAccountRecoverySnapshot? Snapshot, AudioAccountRecoveryOutcome Outcome)>(() =>
        {
            var read = ReadRecoveryHead();
            if (read.PendingVerificationId is not null) return (Snapshot: (AudioAccountRecoverySnapshot?)null,
                Outcome: new AudioAccountRecoveryOutcome(AudioAccountRecoveryStatus.Unsettled));
            if (read.AudioState is not { } data) return (null, new AudioAccountRecoveryOutcome(AudioAccountRecoveryStatus.NoSavedGrant));
            var journal = AudioAccountJournalState.Read(data);
            var scope = AudioAccountScope.FromStoredCredentials(read.Session!, _authClient.SessionAuthority);
            if (journal.LoginId != read.LoginId || journal.Scope != scope) throw new InvalidDataException("Saved audio owner changed.");
            if (journal.Pending.Length != 0) return (null, new AudioAccountRecoveryOutcome(AudioAccountRecoveryStatus.Unsettled));
            try { _ = _audioClock(); }
            catch (PlatformNotSupportedException error)
            { return (null, new AudioAccountRecoveryOutcome(AudioAccountRecoveryStatus.ContinuityUnavailable, error)); }
            var valid = new List<AudioMembershipCheckpoint>(); Exception? continuityFailure = null;
            foreach (var checkpoint in journal.ReadRecoveryCandidates(read.LoginId!.Value, scope))
            {
                if (!AudioAccountRecoverySnapshot.WithinBounds(checkpoint, _audioClock())) continue;
                try { _audioContinuity.RequireCurrent(checkpoint.Continuity); }
                catch (Exception failure) when (failure is CryptographicException or Win32Exception or PlatformNotSupportedException)
                { continuityFailure ??= failure; continue; }
                if (AudioAccountRecoverySnapshot.WithinBounds(checkpoint, _audioClock())) valid.Add(checkpoint);
            }
            if (valid.Count == 0) return (null, new AudioAccountRecoveryOutcome(journal.Checkpoints.Length == 0
                ? AudioAccountRecoveryStatus.NoSavedGrant : continuityFailure is null
                    ? AudioAccountRecoveryStatus.ExpiredOrClockChanged : AudioAccountRecoveryStatus.ContinuityUnavailable, continuityFailure));
            var snapshot = new AudioAccountRecoverySnapshot(read.LoginId!.Value, scope, read.Session!.DisplayName ?? string.Empty,
                read.Session.NebulaId ?? string.Empty, valid, _audioClock);
            return (snapshot, new AudioAccountRecoveryOutcome(AudioAccountRecoveryStatus.Available));
        }).ConfigureAwait(true);
        if (recovered.Snapshot is { } snapshot)
        {
            var epoch = new AccountAudioAuthorization(snapshot.Scope, this, snapshot, offline: true);
            if (!epoch.IsCurrent) return new(AudioAccountRecoveryStatus.ExpiredOrClockChanged);
            Volatile.Read(ref _audioAuthorization)?.Revoke();
            Volatile.Write(ref _audioAuthorization, epoch);
            Volatile.Write(ref _audioAuthorizationError, null);
            _audioMayRefresh = true; // Only a subsequent verified live response can promote it.
        }
        return recovered.Outcome;
    }

    async ValueTask<AudioStoredMembership> IAudioAccountRecoveryStore.RestoreMembershipAsync(AccountAudioAuthorization epoch,
        AudioDeviceIdentity local, AudioDeviceIdentity peer, CancellationToken cancellationToken)
    {
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested(); RequireAudioAuthorization(epoch);
                var snapshot = epoch.Recovery ?? throw new InvalidOperationException("This account has no captured recovery set.");
                var read = ReadRecoveryHead();
                if (read.LoginId != snapshot.LoginId) throw new InvalidDataException("Audio recovery login changed.");
                if (read.PendingVerificationId is not null) return new AudioStoredMembership(null, AudioAccountRecoveryStatus.Unsettled);
                if (read.AudioState is not { } data) return new AudioStoredMembership(null, AudioAccountRecoveryStatus.NoSavedGrant);
                var state = AudioAccountJournalState.Read(data);
                if (state.Scope != epoch.Scope || AudioAccountScope.FromStoredCredentials(read.Session!, _authClient.SessionAuthority) != epoch.Scope)
                    throw new InvalidDataException("Audio recovery account scope changed.");
                if (state.Pending.Length != 0) return new AudioStoredMembership(null, AudioAccountRecoveryStatus.Unsettled);
                var candidate = snapshot.Find(local, peer);
                if (candidate is null || !state.ReadRecoveryCandidates(snapshot.LoginId, epoch.Scope).Contains(candidate))
                    return new AudioStoredMembership(null, AudioAccountRecoveryStatus.NoSavedGrant);
                AudioAccountMembershipEvidence evidence;
                try { evidence = candidate.Restore(snapshot.LoginId, epoch.Scope, local, peer, _audioClock, _audioContinuity); }
                catch (AudioMembershipException error) when (error.Reason is AudioMembershipFailure.Expired or AudioMembershipFailure.ClockChanged)
                { return new AudioStoredMembership(null, AudioAccountRecoveryStatus.ExpiredOrClockChanged, error); }
                catch (Exception error) when (error is CryptographicException or Win32Exception or PlatformNotSupportedException)
                { return new AudioStoredMembership(null, AudioAccountRecoveryStatus.ContinuityUnavailable, error); }
                cancellationToken.ThrowIfCancellationRequested(); RequireAudioAuthorization(epoch);
                return new AudioStoredMembership(evidence, AudioAccountRecoveryStatus.Available);
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is InvalidDataException or AudioJournalStorageException)
        { RevokeAudioAuthorization(); throw; }
        finally { _mutationGate.Release(); }
    }

    private SessionStoreLoadResult ReadRecoveryHead()
    {
        var current = _sessionStore.Load();
        if (!current.Succeeded || current.Session is null)
            throw new AudioJournalStorageException("recovery-read", current.Status.ToString(), current.Failure);
        if (current.Version != _storeVersion || current.LoginId != _durableLoginId || current.LoginId is null)
            throw new AudioJournalStorageException("recovery-read", nameof(SessionStoreWriteStatus.Conflict));
        return current;
    }
}
