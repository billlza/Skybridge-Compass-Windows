using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed partial class WindowsDeviceWorkspace
{
    private readonly CancellationTokenSource _usbBootstrapLifetime = new();
    private readonly SemaphoreSlim _usbBootstrap = new(1, 1), _usbBootstrapClose = new(1, 1);
    private readonly object _usbBootstrapFailures = new();
    private Exception? _usbBootstrapUnreleased, _usbBootstrapCancellationFailure;
    private bool _usbBootstrapStopped;

    internal Task<RemoteControlPairingMaterial> PairUsbPeerAsync(UsbPeerInspection selected,
        AccountDeviceAuthentication authentication, AccountAudioAuthorization account,
        ILanPibApprovalPresenter approval, CancellationToken token, UsbMuxConnector? connector = null)
    {
        ArgumentNullException.ThrowIfNull(approval);
        ArgumentNullException.ThrowIfNull(authentication);
        return RunUsbBootstrapAsync(selected, authentication, account, createIdentity: true, allowOffline: false,
            (current, identity, carrier, requireCurrent, lifetime) =>
                identity.CreatePibInitiator(approval, requireCurrent).PairUsbAsync(current,
                    (request, stage) => ProductBootstrapExchange.ExchangeAsync(
                        cancellation => carrier.OpenAsync(current.Udid, UsbMuxConnector.ControlPort, cancellation),
                        request, LanBootstrapWire.MaximumBytes, stage), lifetime), token, connector);
    }

    internal Task<SignedKemRefreshLease> RefreshUsbPeerKeysAsync(UsbPeerInspection selected,
        AccountDeviceAuthentication? authentication, AccountAudioAuthorization account,
        CancellationToken token, UsbMuxConnector? connector = null) =>
        RunUsbBootstrapAsync(selected, authentication, account, createIdentity: false, allowOffline: true,
            (current, identity, carrier, requireCurrent, lifetime) =>
                identity.CreateKemRefreshInitiator(current.Response.Identity.DeviceID, current.Response.Identity.Fingerprint,
                    requireCurrent, QPeriaptPeerPlatform.LocalVersion()).RefreshUsbAsync(current,
                    (request, stage) => ProductBootstrapExchange.ExchangeAsync(
                        cancellation => carrier.OpenAsync(current.Udid, UsbMuxConnector.ControlPort, cancellation),
                        request, LanBootstrapWire.MaximumBytes, stage), lifetime), token, connector);

    private async Task<T> RunUsbBootstrapAsync<T>(UsbPeerInspection selected,
        AccountDeviceAuthentication? authentication, AccountAudioAuthorization account, bool createIdentity, bool allowOffline,
        Func<UsbPeerInspection, RemoteControlIdentityStore, UsbMuxConnector, Action, CancellationToken, Task<T>> operation,
        CancellationToken token, UsbMuxConnector? connector)
    {
        ArgumentNullException.ThrowIfNull(selected);
        ArgumentNullException.ThrowIfNull(account);
        var workspaceLifetime = _usbBootstrapLifetime.Token;
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(token, workspaceLifetime);
        AudioDeviceIdentity? localForRecovery = null;
        var peerForRecovery = UsbAudioIdentity(selected.Response.Identity.DeviceID, selected.Response.Identity.PublicKey.ToArray());
        void RequireCurrent()
        {
            // A returned public-key lease may outlive this method's linked source.
            // Retain the original cancellation tokens, not a disposed linkage.
            token.ThrowIfCancellationRequested(); workspaceLifetime.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);
            RequireUsbAccount(authentication, account, allowOffline);
            if (localForRecovery is not null && !HasUsbAudioProtocolCandidate(account, localForRecovery, peerForRecovery))
                throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
        }
        RequireCurrent();
        if (!await _usbBootstrap.WaitAsync(0, scope.Token).ConfigureAwait(false))
            throw new InvalidOperationException("Another USB bootstrap transaction is already active.");
        try
        {
            RequireCurrent();
            lock (_usbBootstrapFailures)
            {
                if (_usbBootstrapUnreleased is { } retained)
                    throw new InvalidOperationException("USB bootstrap has an unreleased native owner.", retained);
            }
            var carrier = connector ?? UsbMuxConnector.WindowsService();
            var current = await new UsbPeerDiscoveryClient(carrier).InspectAsync(selected.Udid, scope.Token).ConfigureAwait(false);
            RequireCurrent();
            var expected = selected.Response.Identity;
            var actual = current.Response.Identity;
            if (actual.DeviceID != expected.DeviceID || actual.Algorithm != expected.Algorithm ||
                actual.Fingerprint != expected.Fingerprint || !actual.PublicKey.AsSpan().SequenceEqual(expected.PublicKey.AsSpan()))
                throw new InvalidDataException("The selected USB device identity changed. Refresh before connecting.");
            RemoteControlIdentityStore identity;
            await _operations.WaitAsync(scope.Token).ConfigureAwait(false);
            try
            {
                RequireCurrent();
                _identity ??= createIdentity
                    ? await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, scope.Token).ConfigureAwait(false)
                    : await RemoteControlIdentityStore.LoadExistingAsync(_stateDirectory, _displayName, scope.Token).ConfigureAwait(false);
                identity = _identity;
                var local = identity.PublicMaterial;
                localForRecovery = UsbAudioIdentity(local.DeviceId, local.ProtocolPublicKey.ToArray());
                RequireCurrent();
            }
            finally { _operations.Release(); }
            return await operation(current, identity, carrier, RequireCurrent, scope.Token).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            if (ProductBootstrapReleaseException.ContainsUnreleasedOwner(error))
            {
                lock (_usbBootstrapFailures) _usbBootstrapUnreleased = error;
            }
            throw;
        }
        finally { _usbBootstrap.Release(); }
    }

    private static AudioDeviceIdentity UsbAudioIdentity(string deviceId, byte[] publicKey) =>
        AudioDeviceIdentity.FromRegistryBinding(new CurrentPathProtocolIdentityBinding(
            deviceId, CurrentPathProtocolSigningAlgorithm.MLDsa65, publicKey));

    // This limits the control route to the same saved device pair. Playback still
    // restores the protected checkpoint against actual MAIN identities separately.
    private static bool IsUsbAudioRouteCurrent(AccountAudioAuthorization account, AudioDeviceIdentity local, AudioDeviceIdentity peer) =>
        account.IsCurrent && (!account.IsOffline || account.Recovery is { } recovery &&
            recovery.Scope == account.Scope && recovery.Find(local, peer) is not null);

    private static bool HasUsbAudioProtocolCandidate(AccountAudioAuthorization account, AudioDeviceIdentity local, AudioDeviceIdentity discoveredPeer) =>
        account.IsCurrent && (!account.IsOffline || account.Recovery is { } recovery &&
            recovery.Scope == account.Scope && recovery.HasProtocolCandidate(local, discoveredPeer));

    // A missing bearer is legal only for an existing bounded offline audio
    // publication. This never creates ordinary account-request authentication.
    private static void RequireUsbAccount(AccountDeviceAuthentication? authentication, AccountAudioAuthorization account, bool allowOffline)
    {
        account.RequireCurrent();
        if (account.IsOffline)
        {
            if (!allowOffline) throw new InvalidOperationException("Verify this account online before pairing a new USB device.");
            if (authentication is not null) account.RequireAuthentication(authentication);
            return;
        }
        if (authentication is null) throw new InvalidOperationException("Online USB access requires current account authentication.");
        account.RequireAuthentication(authentication);
        if (!SessionJwtValidator.TryValidate(authentication.AccessToken, authentication.Authority, authentication.Subject,
                requireUnexpired: true, out _, out _))
            throw new InvalidOperationException("The account credential expired or changed during USB bootstrap.");
    }

    private async Task StopUsbBootstrapAsync()
    {
        await _usbBootstrapClose.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_usbBootstrapStopped) return;
            try { _usbBootstrapLifetime.Cancel(); }
            catch (Exception error)
            {
                lock (_usbBootstrapFailures) _usbBootstrapCancellationFailure ??= error;
            }
            if (!await _usbBootstrap.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false))
            {
                var timeout = new TimeoutException("USB bootstrap still owns its approval or native operation; the identity remains retained.");
                lock (_usbBootstrapFailures)
                {
                    if (_usbBootstrapCancellationFailure is { } cancellation) throw new AggregateException(cancellation, timeout);
                }
                throw timeout;
            }
            try
            {
                lock (_usbBootstrapFailures)
                {
                    if (_usbBootstrapUnreleased is { } retained)
                        throw new InvalidOperationException("USB bootstrap native cleanup is unconfirmed.",
                            _usbBootstrapCancellationFailure is null ? retained : new AggregateException(_usbBootstrapCancellationFailure, retained));
                    if (_usbBootstrapCancellationFailure is { } failure)
                        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
                }
                _usbBootstrapLifetime.Dispose(); _usbBootstrapStopped = true;
            }
            finally { _usbBootstrap.Release(); }
        }
        finally { _usbBootstrapClose.Release(); }
    }
}
