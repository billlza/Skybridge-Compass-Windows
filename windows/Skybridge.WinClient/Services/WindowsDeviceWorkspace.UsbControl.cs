using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed partial class WindowsDeviceWorkspace
{
    internal async Task<LanProductControlSession> ConnectUsbControlAsync(UsbPeerInspection selected,
        AccountDeviceAuthentication authentication, AccountAudioAuthorization account,
        RemoteControlViewerAccount presentation, CancellationToken token, UsbMuxConnector? connector = null)
    {
        ArgumentNullException.ThrowIfNull(selected); ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(authentication); ArgumentNullException.ThrowIfNull(presentation);
        await _controlOperations.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); account.RequireAuthentication(authentication);
            await RemoveStoppedControlSessionsAsync().ConfigureAwait(false);
            string peerId = RemoteControlHandshakeBinding.CanonicalDeviceId(selected.Response.Identity.DeviceID);
            if (_controlSessions.TryGetValue(peerId, out var existing))
            {
                existing.RequireUsbRoute(selected, account.Scope);
                return existing;
            }
            if (_controlSessions.Count >= 8) throw new InvalidOperationException("Eight device sessions are already open. Disconnect before adding another.");
            var workspaceLifetime = _usbBootstrapLifetime.Token;
            var session = await RunUsbBootstrapAsync(selected, authentication, account, createIdentity: false, allowOffline: true,
                async (current, identity, carrier, requireCurrent, lifetime) =>
                {
                    var refresh = await identity.CreateKemRefreshInitiator(current.Response.Identity.DeviceID,
                        current.Response.Identity.Fingerprint, requireCurrent, QPeriaptPeerPlatform.LocalVersion())
                        .RefreshUsbAsync(current, (request, stage) => ProductBootstrapExchange.ExchangeAsync(
                            cancellation => carrier.OpenAsync(current.Udid, UsbMuxConnector.ControlPort, cancellation),
                            request, LanBootstrapWire.MaximumBytes, stage), lifetime).ConfigureAwait(false);
                    requireCurrent();
                    var prepared = identity.PrepareUsbAuthentication(UsbControlRoute.From(current), refresh, presentation);
                    return await LanProductControlSession.ConnectUsbAsync(prepared, carrier, account.Scope,
                        () => !_disposed && account.IsCurrent, lifetime, token, workspaceLifetime).ConfigureAwait(false);
                }, token, connector).ConfigureAwait(false);
            lock (_stateGate) _controlSessions.Add(peerId, session);
            // Like the network path, retain an installed MAIN even if starting a
            // feature fails. Explicit disconnect drains the actual consumer.
            if (_audioReceiveHost is { } receiver) await receiver.AttachAsync(session, token).ConfigureAwait(false);
            return session;
        }
        finally { _controlOperations.Release(); }
    }
}
