using System.Diagnostics;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>Consumes real device-page registry results using only the publication captured
/// in that request's authentication. Observations can revoke; they never issue or renew grants.</summary>
internal sealed class AudioAccountRegistryObserver(AudioAccountMembershipProvider provider,
    Func<AudioAuthorizationTime>? clock = null) : IAccountDeviceRegistryObserver
{
    private readonly Func<AudioAuthorizationTime> _clock = clock ?? AudioAuthorizationTime.ReadWindows;
    public async ValueTask<IAccountDeviceRegistryObservation?> BeginAsync(AccountDeviceAuthentication authentication,
        CurrentPathProtocolIdentityBinding binding, AccountDeviceRegistryRequest request, CancellationToken cancellationToken,
        AccountDeviceEntry? removalTarget = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (authentication.AudioAuthorization is not { } epoch) return null;
        var caller = AudioDeviceIdentity.FromRegistryBinding(binding);
        var target = removalTarget is null ? null : new AudioCheckpointIdentity(removalTarget.DeviceId, removalTarget.Algorithm, removalTarget.Fingerprint);
        var store = epoch.Observations;
        var ticket = store is null ? null : await store.BeginAsync(epoch, caller, request, target, cancellationToken).ConfigureAwait(false);
        return new Observation(provider, authentication, epoch, caller, _clock(), _clock, request, store, ticket);
    }

    private sealed class Observation(AudioAccountMembershipProvider provider, AccountDeviceAuthentication authentication,
        AccountAudioAuthorization epoch, AudioDeviceIdentity caller, AudioAuthorizationTime started,
        Func<AudioAuthorizationTime> clock, AccountDeviceRegistryRequest request,
        IAudioAccountObservationStore? store, AudioJournalTicket? ticket) : IAccountDeviceRegistryObservation
    {
        private AudioRegistryObservation? _registry;
        private AudioCheckpointIdentity? _removed;
        private bool _callerRejected;
        public void Listed(AccountDeviceRosterSnapshot snapshot)
        {
            bool applied;
            try
            {
                var received = clock();
                applied = provider.ObserveRegistryResponse(epoch, authentication, caller, snapshot, started, received);
                if (applied) _registry = AudioRegistryObservation.FromResponse(authentication, caller, snapshot, started, received);
            }
            catch (AudioMembershipException error) when (error.Reason == AudioMembershipFailure.InvalidResponse)
            { throw new InvalidDataException("The account registry response cannot provide a fresh audio authorization observation.", error); }
            Report(applied, "list");
        }
        public void Removed(AccountDeviceEntry target)
        {
            Report(provider.Removed(epoch, target), "removal");
            _removed = new(target.DeviceId, target.Algorithm, target.Fingerprint);
        }
        public void Rejected(CurrentPathSignalServerException error)
        {
            Report(provider.ObserveCallerRejection(epoch, caller, error), "denial");
            _callerRejected |= AudioAccountMembershipProvider.IsDeviceDenial(error);
        }
        public async ValueTask CompleteAsync(Exception? failure)
        {
            AudioJournalCompletion? completion = null;
            if (store is not null && ticket is not null)
                completion = await store.CompleteAsync(ticket, new(_registry, _removed, _callerRejected), failure).ConfigureAwait(false);
            Debug.WriteLine($"Audio account registry {request} settled: {failure?.GetType().Name ?? "success"}; journal={completion?.ToString() ?? "process-local"}.");
        }
        private static void Report(bool applied, string operation) =>
            Debug.WriteLine($"Audio account registry {operation}: {(applied ? "applied" : "no current matching authorization effect")}.");
    }
}
