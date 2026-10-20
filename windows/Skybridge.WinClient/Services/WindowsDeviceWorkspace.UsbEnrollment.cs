using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed partial class WindowsDeviceWorkspace
{
    private readonly CancellationTokenSource _usbEnrollmentLifetime = new();
    private readonly SemaphoreSlim _usbEnrollment = new(1, 1), _usbEnrollmentClose = new(1, 1);
    private readonly object _usbEnrollmentFailures = new();
    private Exception? _usbEnrollmentUnreleased, _usbEnrollmentCancellationFailure;
    private bool _usbEnrollmentStopped;

    internal async Task<RemoteControlPairingMaterial> PairUsbPeerAsync(UsbPeerInspection selected,
        AccountDeviceAuthentication authentication, AccountAudioAuthorization account,
        ILanPibApprovalPresenter approval, CancellationToken token, UsbMuxConnector? connector = null)
    {
        ArgumentNullException.ThrowIfNull(selected); ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(account); ArgumentNullException.ThrowIfNull(approval);
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(token, _usbEnrollmentLifetime.Token);
        void RequireCurrent()
        {
            scope.Token.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);
            // Offline recovery exposes an audio capability, not authority to
            // create a new general-purpose device trust record.
            if (account.IsOffline) throw new InvalidOperationException("Verify this account online before pairing a new USB device.");
            account.RequireAuthentication(authentication);
            if (!SessionJwtValidator.TryValidate(authentication.AccessToken, authentication.Authority,
                    authentication.Subject, requireUnexpired: true, out _, out _))
                throw new InvalidOperationException("The account credential expired or changed during USB pairing.");
        }
        RequireCurrent();
        if (!await _usbEnrollment.WaitAsync(0, scope.Token).ConfigureAwait(false))
            throw new InvalidOperationException("Another USB pairing transaction is already active.");
        try
        {
            RequireCurrent();
            lock (_usbEnrollmentFailures)
            {
                if (_usbEnrollmentUnreleased is { } retained)
                    throw new InvalidOperationException("USB enrollment has an unreleased native owner.", retained);
            }
            var carrier = connector ?? UsbMuxConnector.WindowsService();
            var current = await new UsbPeerDiscoveryClient(carrier).InspectAsync(selected.Udid, scope.Token).ConfigureAwait(false);
            RequireCurrent();
            var expected = selected.Response.Identity;
            var actual = current.Response.Identity;
            if (actual.DeviceID != expected.DeviceID || actual.Algorithm != expected.Algorithm ||
                actual.Fingerprint != expected.Fingerprint || !actual.PublicKey.AsSpan().SequenceEqual(expected.PublicKey.AsSpan()))
                throw new InvalidDataException("The selected USB device identity changed. Refresh before pairing.");
            RemoteControlIdentityStore identity;
            await _operations.WaitAsync(scope.Token).ConfigureAwait(false);
            try
            {
                RequireCurrent();
                _identity ??= await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, scope.Token).ConfigureAwait(false);
                identity = _identity;
            }
            finally { _operations.Release(); }
            var transaction = identity.CreatePibInitiator(approval, RequireCurrent);
            return await transaction.PairUsbAsync(current, (request, lifetime) =>
                ProductBootstrapExchange.ExchangeAsync(
                    cancellation => carrier.OpenAsync(current.Udid, UsbMuxConnector.ControlPort, cancellation),
                    request, LanBootstrapWire.MaximumBytes, lifetime), scope.Token).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            if (ProductBootstrapReleaseException.ContainsUnreleasedOwner(error))
            {
                lock (_usbEnrollmentFailures) _usbEnrollmentUnreleased = error;
            }
            throw;
        }
        finally { _usbEnrollment.Release(); }
    }

    private async Task StopUsbEnrollmentAsync()
    {
        await _usbEnrollmentClose.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_usbEnrollmentStopped) return;
            try { _usbEnrollmentLifetime.Cancel(); }
            catch (Exception error)
            {
                lock (_usbEnrollmentFailures) _usbEnrollmentCancellationFailure ??= error;
            }
            if (!await _usbEnrollment.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false))
            {
                var timeout = new TimeoutException("USB enrollment still owns its approval or native operation; the identity remains retained.");
                lock (_usbEnrollmentFailures)
                {
                    if (_usbEnrollmentCancellationFailure is { } cancellation) throw new AggregateException(cancellation, timeout);
                }
                throw timeout;
            }
            try
            {
                lock (_usbEnrollmentFailures)
                {
                    if (_usbEnrollmentUnreleased is { } retained)
                        throw new InvalidOperationException("USB enrollment native cleanup is unconfirmed.",
                            _usbEnrollmentCancellationFailure is null ? retained : new AggregateException(_usbEnrollmentCancellationFailure, retained));
                    if (_usbEnrollmentCancellationFailure is { } failure)
                        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
                }
                _usbEnrollmentLifetime.Dispose(); _usbEnrollmentStopped = true;
            }
            finally { _usbEnrollment.Release(); }
        }
        finally { _usbEnrollmentClose.Release(); }
    }
}
