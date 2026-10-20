using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed partial class WindowsDeviceWorkspace
{
    internal sealed record ConnectedUsbPeer(UsbControlRoute Route, bool AudioReceiverInstalled);

    internal IReadOnlyList<ConnectedUsbPeer> ReadConnectedUsbPeers()
    {
        lock (_stateGate)
        {
            if (_disposed) return [];
            var connected = new List<ConnectedUsbPeer>();
            foreach (var session in _controlSessions.Values)
                if (session.IsReady && session.Carrier is ProductControlCarrier.Usb usb)
                    connected.Add(new(usb.Route, OriginalAudioFiles.UsbReceiverFor(session) is not null &&
                        _audioReceiveHost?.OwnsSession(session) == true));
            return connected;
        }
    }

    internal async Task<LanProductControlSession> ConnectUsbControlAsync(UsbPeerInspection selected,
        AccountDeviceAuthentication? authentication, AccountAudioAuthorization account,
        RemoteControlViewerAccount presentation, CancellationToken token, UsbMuxConnector? connector = null)
    {
        ArgumentNullException.ThrowIfNull(selected); ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(presentation);
        await _controlOperations.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); RequireUsbAccount(authentication, account, allowOffline: true);
            await RemoveStoppedControlSessionsAsync().ConfigureAwait(false);
            string peerId = RemoteControlHandshakeBinding.CanonicalDeviceId(selected.Response.Identity.DeviceID);
            if (_controlSessions.TryGetValue(peerId, out var existing))
            {
                existing.RequireUsbRoute(selected, account.Scope);
                var binding = existing.RequireAudioIdentityBinding();
                if (!IsUsbAudioRouteCurrent(account, AudioDeviceIdentity.From(binding.LocalDeviceId, binding.LocalProtocolIdentity),
                        AudioDeviceIdentity.From(binding.PeerDeviceId, binding.PeerProtocolIdentity)))
                    throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
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
                    var local = identity.PublicMaterial;
                    var localForRecovery = UsbAudioIdentity(local.DeviceId, local.ProtocolPublicKey.ToArray());
                    var peerForRecovery = UsbAudioIdentity(current.Response.Identity.DeviceID, current.Response.Identity.PublicKey.ToArray());
                    AudioDeviceIdentity? admittedPeer = null;
                    bool IsCurrent()
                    {
                        if (_disposed) return false;
                        var actual = Volatile.Read(ref admittedPeer);
                        return actual is null ? HasUsbAudioProtocolCandidate(account, localForRecovery, peerForRecovery)
                            : IsUsbAudioRouteCurrent(account, localForRecovery, actual);
                    }
                    var prepared = identity.PrepareUsbAuthentication(UsbControlRoute.From(current), refresh, presentation);
                    var admitted = await LanProductControlSession.ConnectUsbAsync(prepared, carrier, account.Scope,
                        IsCurrent, lifetime, token, workspaceLifetime).ConfigureAwait(false);
                    try
                    {
                        var binding = admitted.RequireAudioIdentityBinding();
                        if (AudioDeviceIdentity.From(binding.LocalDeviceId, binding.LocalProtocolIdentity) != localForRecovery)
                            throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
                        Volatile.Write(ref admittedPeer, AudioDeviceIdentity.From(binding.PeerDeviceId, binding.PeerProtocolIdentity));
                        if (!IsCurrent()) throw new AudioMembershipException(AudioMembershipFailure.IdentityChanged);
                        return admitted;
                    }
                    catch (Exception failure)
                    {
                        try { await admitted.DisposeAsync().ConfigureAwait(false); }
                        catch (Exception cleanup)
                        { throw new ProductBootstrapReleaseException(admitted, new AggregateException(failure, cleanup)); }
                        throw;
                    }
                }, token, connector).ConfigureAwait(false);
            lock (_stateGate) _controlSessions.Add(peerId, session);
            var privateDirectory = Path.Combine(_stateDirectory, "audio-playback");
            Directory.CreateDirectory(privateDirectory);
            OriginalAudioFiles.BindUsb(session, connector ?? UsbMuxConnector.WindowsService(), privateDirectory);
            // Like the network path, retain an installed MAIN even if starting a
            // feature fails. Explicit disconnect drains the actual consumer.
            if (_audioReceiveHost is { } receiver) await receiver.AttachAsync(session, token).ConfigureAwait(false);
            return session;
        }
        finally { _controlOperations.Release(); }
    }
}
