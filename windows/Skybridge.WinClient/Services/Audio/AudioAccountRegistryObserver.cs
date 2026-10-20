using System.Diagnostics;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>Consumes real device-page registry results using only the publication captured
/// in that request's authentication. Observations can revoke; they never issue or renew grants.</summary>
internal sealed class AudioAccountRegistryObserver(AudioAccountMembershipProvider provider,
    Func<AudioAuthorizationTime>? clock = null) : IAccountDeviceRegistryObserver
{
    private readonly Func<AudioAuthorizationTime> _clock = clock ?? AudioAuthorizationTime.ReadWindows;
    public ValueTask<IAccountDeviceRegistryObservation?> BeginAsync(AccountDeviceAuthentication authentication,
        CurrentPathProtocolIdentityBinding binding, AccountDeviceRegistryRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IAccountDeviceRegistryObservation? observation = authentication.AudioAuthorization is { } epoch
            ? new Observation(provider, authentication, epoch, AudioDeviceIdentity.FromRegistryBinding(binding), _clock(), _clock, request)
            : null;
        return ValueTask.FromResult(observation);
    }

    private sealed class Observation(AudioAccountMembershipProvider provider, AccountDeviceAuthentication authentication,
        AccountAudioAuthorization epoch, AudioDeviceIdentity caller, AudioAuthorizationTime started,
        Func<AudioAuthorizationTime> clock, AccountDeviceRegistryRequest request) : IAccountDeviceRegistryObservation
    {
        public void Listed(AccountDeviceRosterSnapshot snapshot)
        {
            bool applied;
            try { applied = provider.ObserveRegistryResponse(epoch, authentication, caller, snapshot, started, clock()); }
            catch (AudioMembershipException error) when (error.Reason == AudioMembershipFailure.InvalidResponse)
            { throw new InvalidDataException("The account registry response cannot provide a fresh audio authorization observation.", error); }
            Report(applied, "list");
        }
        public void Removed(AccountDeviceEntry target) => Report(provider.Removed(epoch, target), "removal");
        public void Rejected(CurrentPathSignalServerException error) => Report(provider.ObserveCallerRejection(epoch, caller, error), "denial");
        public ValueTask CompleteAsync(Exception? failure)
        {
            // This observer still owns process-local evidence only. Completion
            // reports the real outcome; it does not save, renew or restore a grant.
            Debug.WriteLine($"Audio account registry {request} settled: {failure?.GetType().Name ?? "success"}.");
            return ValueTask.CompletedTask;
        }
        private static void Report(bool applied, string operation) =>
            Debug.WriteLine($"Audio account registry {operation}: {(applied ? "applied" : "no current matching authorization effect")}.");
    }
}
