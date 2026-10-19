using System.Net.Http;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>Read-only account GET; never calls the device-page presence/enrollment flow.</summary>
internal sealed class AudioAccountMembershipClient
{
    private readonly HttpClient _http;
    private readonly Func<AudioAuthorizationTime> _clock;
    private readonly TimeSpan _timeout;
    internal AudioAccountMembershipClient(HttpClient http, Func<AudioAuthorizationTime>? clock = null, TimeSpan? timeout = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _clock = clock ?? AudioAuthorizationTime.ReadWindows;
        _timeout = timeout ?? TimeSpan.FromMilliseconds(AudioAccountMembershipEvidence.MaximumRequestMilliseconds);
        if (_timeout <= TimeSpan.Zero || _timeout.TotalMilliseconds > AudioAccountMembershipEvidence.MaximumRequestMilliseconds)
            throw new ArgumentOutOfRangeException(nameof(timeout));
    }
    internal async Task<AudioRegistryObservation> QueryAsync(AccountDeviceAuthentication authentication,
        AudioSessionIdentityBinding identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var binding = AudioDeviceIdentity.QueryBinding(identity.LocalDeviceId, identity.LocalProtocolIdentity);
        var local = AudioDeviceIdentity.From(identity.LocalDeviceId, identity.LocalProtocolIdentity);
        var client = new CurrentPathSignalServerClient(_http, new CurrentPathSignalServerClientOptions(
            bearerTokenProvider: _ => Task.FromResult(authentication.AccessToken),
            tenantIdProvider: _ => Task.FromResult(authentication.TenantId), clientVersion: "1.0.2"));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_timeout);
        var started = _clock();
        AccountDeviceRosterSnapshot snapshot;
        try { snapshot = await client.ListAccountDevicesAsync(binding, deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException failure) when (!cancellationToken.IsCancellationRequested &&
            (deadline.IsCancellationRequested || failure.InnerException is TimeoutException))
        { throw new AudioMembershipQueryTimeoutException(failure); }
        // A complete fresh response may revoke other grants even when its requester just canceled.
        return AudioRegistryObservation.FromResponse(authentication, local, snapshot, started, _clock());
    }
}
