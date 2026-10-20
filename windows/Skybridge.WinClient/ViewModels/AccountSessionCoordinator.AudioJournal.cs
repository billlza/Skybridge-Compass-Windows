using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

namespace Skybridge.WinClient.ViewModels;

public sealed partial class AccountSessionCoordinator : IAudioAccountObservationStore
{
    async ValueTask<AudioJournalTicket> IAudioAccountObservationStore.BeginAsync(AccountAudioAuthorization epoch,
        AudioDeviceIdentity caller, AccountDeviceRegistryRequest kind, AudioCheckpointIdentity? removalTarget,
        CancellationToken cancellationToken, AudioDeviceIdentity? membershipPeer)
    {
        await _mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Even an uncontended semaphore await can complete on the UI
            // thread. Keep the protected file read/flush/replace off that thread.
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested(); RequireAudioAuthorization(epoch);
                var state = ReadOwnedAudioJournal(epoch);
                var request = new AudioJournalPending(Guid.NewGuid(), kind, AudioCheckpointIdentity.From(caller), removalTarget,
                    membershipPeer is null ? null : AudioCheckpointIdentity.From(membershipPeer));
                var updated = state.Begin(request);
                CommitAudioJournal(updated);
                // Once preparation commits, always return its ownership, even
                // if canceled meanwhile. The caller must settle this entry.
                return new AudioJournalTicket(state.LoginId, epoch, request);
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { _mutationGate.Release(); }
    }

    async ValueTask<AudioJournalCompletion> IAudioAccountObservationStore.CompleteAsync(AudioJournalTicket ticket,
        AudioJournalEffects effects, Exception? failure)
    {
        // A canceled UI waiter cannot skip persistence of a response already
        // observed. This gate serializes with token rotation and sign-out; it
        // is never acquired while holding a playback/transport effect lock.
        await _mutationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await Task.Run(() =>
            {
                if (!ReferenceEquals(ReadAudioAuthorization(), ticket.Epoch) || !ticket.Epoch.IsCurrent ||
                    _durableLoginId != ticket.LoginId)
                    return AudioJournalCompletion.RetiredOwner;
                var state = ReadOwnedAudioJournal(ticket.Epoch);
                var settled = state.Complete(ticket.Request, effects, failure);
                CommitAudioJournal(settled.State);
                return settled.Completion;
            }).ConfigureAwait(false);
        }
        finally { _mutationGate.Release(); }
    }

    private AudioAccountJournalState ReadOwnedAudioJournal(AccountAudioAuthorization epoch)
    {
        if (_durableLoginId is not { } login || login == Guid.Empty || _storeVersion is null)
            throw new InvalidOperationException("Audio journaling requires a captured durable account owner.");
        var current = _sessionStore.Load();
        if (!current.Succeeded)
        {
            RevokeAudioAuthorization();
            throw new AudioJournalStorageException("read", current.Status.ToString(), current.Failure);
        }
        if (current.Version != _storeVersion || current.LoginId != login)
        {
            RevokeAudioAuthorization();
            throw new AudioJournalStorageException("read", nameof(SessionStoreWriteStatus.Conflict));
        }
        if (current.PendingVerificationId is not null)
            throw new InvalidOperationException("Audio admission requires account verification to finish durably.");
        if (current.AudioState is not { } payload) return AudioAccountJournalState.Empty(login, epoch.Scope);
        AudioAccountJournalState state;
        try { state = AudioAccountJournalState.Read(payload); }
        catch (InvalidDataException) { RevokeAudioAuthorization(); throw; }
        if (state.LoginId != login)
        {
            RevokeAudioAuthorization();
            throw new InvalidDataException("Audio journal is bound to another login.");
        }
        // Only an already verified online account publication reaches this
        // mutation path. A changed protected scope retires old journal data;
        // it cannot transfer its checkpoints into the new account scope.
        return state.Scope == epoch.Scope ? state : AudioAccountJournalState.Empty(login, epoch.Scope);
    }

    private void CommitAudioJournal(AudioAccountJournalState state)
    {
        state.Validate();
        if (_sessionStore is not ISessionAudioStateStore storage)
        {
            RevokeAudioAuthorization();
            throw new NotSupportedException("The account store cannot persist audio observations.");
        }
        var saved = storage.WriteAudioState(JsonSerializer.SerializeToElement(state), RequireStoreVersion(), state.LoginId);
        if (!saved.Succeeded)
        {
            RevokeAudioAuthorization();
            throw new AudioJournalStorageException("commit", saved.Status.ToString(), saved.Failure, saved.CleanupFailure);
        }
        AdoptStoredState(saved);
    }
}
