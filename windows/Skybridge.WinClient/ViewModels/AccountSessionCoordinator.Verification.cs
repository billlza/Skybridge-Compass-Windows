using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;

namespace Skybridge.WinClient.ViewModels;

public sealed partial class AccountSessionCoordinator
{
    // Called with the account mutation gate held. A marker covers the complete
    // refresh + live-user verification sequence, including rotated-token writes.
    private async Task<AccountSessionResult> HydrateWithVerificationAsync(SessionStoreLoadResult captured,
        ValidatedSessionToken claims, bool requestRefresh)
    {
        var persisted = captured.Session ?? throw new InvalidOperationException("Missing captured credentials.");
        AudioAccountScope? previousScope = null;
        bool hasUnsettledAudio = false;
        if (captured.AudioState is { } audio)
        {
            try
            {
                var journal = AudioAccountJournalState.Read(audio);
                if (journal.LoginId != captured.LoginId || journal.Scope.Authority != persisted.Authority || journal.Scope.Subject != persisted.Subject)
                    throw new InvalidDataException("Stored audio authority belongs to another account.");
                previousScope = journal.Scope;
                hasUnsettledAudio = journal.Pending.Length != 0;
            }
            catch (InvalidDataException)
            {
                RevokeAudioAuthorization();
                return AccountSessionResult.Failed(AccountSessionFailureKind.SessionPersistenceFailed, "InvalidAudioJournal");
            }
        }

        ISessionVerificationStore? storage = null;
        Guid? observation = null;
        // Schema-1 credentials cannot contain audio authority or a durable
        // login. Their existing live migration path still issues no offline grant.
        if (captured.LoginId is { } login)
        {
            if (_sessionStore is not ISessionVerificationStore capable)
            {
                RevokeAudioAuthorization();
                return AccountSessionResult.Failed(AccountSessionFailureKind.SessionPersistenceFailed, "VerificationStoreUnavailable");
            }
            storage = capable;
            observation = Guid.NewGuid();
            bool retireUnsettled = captured.PendingVerificationId is not null ||
                !requestRefresh && ReadAudioAuthorization() is not { IsCurrent: true } && hasUnsettledAudio;
            var prepared = await Task.Run(() => storage.BeginVerification(RequireStoreVersion(), login,
                observation.Value, retireUnsettled)).ConfigureAwait(true);
            if (!prepared.Succeeded) return FailedVerificationStorage("preparation", prepared);
            AdoptStoredState(prepared);
            if (retireUnsettled) RevokeAudioAuthorization();
        }

        bool scopeChanged = false;
        void ObserveVerifiedToken(string token)
        {
            if (previousScope is null) return;
            try
            {
                var scope = AudioAccountScope.From(AccountDeviceAuthentication.FromVerifiedSession(token,
                    _authClient.SessionAuthority, claims.Subject));
                scopeChanged |= scope != previousScope;
            }
            catch (InvalidDataException) { scopeChanged = true; }
        }

        AccountSessionResult result;
        try { result = await RevalidatePersistedSessionAsync(persisted, claims, requestRefresh, ObserveVerifiedToken).ConfigureAwait(true); }
        catch (Exception primary)
        {
            RevokeAudioAuthorization();
            if (storage is not null && observation is { } owned && captured.LoginId is { } ownerLogin)
            {
                try
                {
                    var settled = await Task.Run(() => storage.CompleteVerification(RequireStoreVersion(), ownerLogin,
                        owned, retireAudio: true)).ConfigureAwait(true);
                    if (!settled.Succeeded) throw new AccountVerificationStorageException("completion", settled);
                    AdoptStoredState(settled);
                }
                catch (Exception secondary)
                { throw new AggregateException("Account verification and durable settlement failed.", primary, secondary); }
            }
            throw;
        }

        // A committed tombstone removed the marker together with the login.
        // A conflicting writer owns the replacement: never clear its marker.
        bool retiredOwner = result.SignedOut || result.ErrorCode == nameof(SessionStoreWriteStatus.Conflict);
        if (!retiredOwner && storage is not null && observation is { } id && captured.LoginId is { } expectedLogin)
        {
            bool preserve = !scopeChanged && (result.Success ||
                result.FailureKind == AccountSessionFailureKind.Network && AudioMembershipRequestFailure.IsTemporary(result.AuthenticationFailure));
            if (!preserve && ReadAudioAuthorization() is { IsOffline: true }) RevokeAudioAuthorization();
            var settled = await Task.Run(() => storage.CompleteVerification(RequireStoreVersion(), expectedLogin,
                id, retireAudio: !preserve)).ConfigureAwait(true);
            if (!settled.Succeeded) return FailedVerificationStorage("completion", settled, result);
            AdoptStoredState(settled);
        }
        if (result.Success && !result.SignedOut)
        {
            PublishAudioAuthorization(preserveExisting: requestRefresh || ReadAudioAuthorization() is { IsOffline: true });
            RaiseIdentityChanged();
        }
        else if (!requestRefresh && !scopeChanged && result.FailureKind == AccountSessionFailureKind.Network &&
            AudioMembershipRequestFailure.IsTemporary(result.AuthenticationFailure) && captured.LoginId is not null)
        {
            try { result = result with { OfflineAudio = await RestoreOfflineAudioAsync().ConfigureAwait(true) }; }
            catch (Exception error) when (error is InvalidDataException or AudioJournalStorageException)
            {
                RevokeAudioAuthorization();
                return AccountSessionResult.Failed(AccountSessionFailureKind.SessionPersistenceFailed, "OfflineAudioRecoveryInvalid", result.AuthenticationFailure)
                    with { OfflineAudio = new(AudioAccountRecoveryStatus.InvalidStoredState, error) };
            }
        }
        return result;
    }

    private AccountSessionResult FailedVerificationStorage(string stage, SessionStoreWriteResult storage,
        AccountSessionResult? preceding = null)
    {
        RevokeAudioAuthorization();
        return AccountSessionResult.Failed(AccountSessionFailureKind.SessionPersistenceFailed,
            $"Verification{stage}:{storage.Status}", preceding?.AuthenticationFailure) with {
            VerificationFailure = new(stage, storage, preceding?.FailureKind, preceding?.ErrorCode)
        };
    }
}

internal sealed record AccountVerificationFailure(string Stage, SessionStoreWriteResult Storage,
    AccountSessionFailureKind? PreviousFailureKind, string? PreviousErrorCode);
internal sealed class AccountVerificationStorageException(string stage, SessionStoreWriteResult result)
    : IOException($"Account verification {stage} failed: {result.Status}.")
{
    internal SessionStoreWriteResult Result { get; } = result;
}
