using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

/// <summary>One prepared handshake from the application's existing paired identity store.</summary>
internal sealed class ProductPeerAuthentication : IDisposable
{
    private readonly Action _requireCurrent;
    internal ProductPeerAuthentication(DiscoveryPeerEndpoint endpoint, ProductHandshakePeerContext peer,
        WebRtcProductPqcHandshakeCryptoProvider crypto, RemoteControlSecurityIdentity localIdentity,
        RemoteControlPairingMaterial localPairing)
        : this(new ProductPeerRoute.Network(endpoint), peer, crypto, localIdentity, localPairing, static () => { }) { }

    internal ProductPeerAuthentication(UsbControlRoute route, ProductHandshakePeerContext peer,
        WebRtcProductPqcHandshakeCryptoProvider crypto, RemoteControlSecurityIdentity localIdentity,
        RemoteControlPairingMaterial localPairing, Action requireCurrent)
        : this(new ProductPeerRoute.Usb(route), peer, crypto, localIdentity, localPairing, requireCurrent) { }

    private ProductPeerAuthentication(ProductPeerRoute route, ProductHandshakePeerContext peer,
        WebRtcProductPqcHandshakeCryptoProvider crypto, RemoteControlSecurityIdentity localIdentity,
        RemoteControlPairingMaterial localPairing, Action requireCurrent)
    {
        Route = route; Peer = peer; Crypto = crypto; LocalIdentity = localIdentity;
        LocalPairing = localPairing; _requireCurrent = requireCurrent;
    }
    internal ProductPeerRoute Route { get; }
    internal DiscoveryPeerEndpoint Endpoint => Route is ProductPeerRoute.Network network ? network.Endpoint
        : throw new InvalidOperationException("The prepared USB peer has no network discovery endpoint.");
    internal ProductHandshakePeerContext Peer { get; }
    internal WebRtcProductPqcHandshakeCryptoProvider Crypto { get; }
    internal RemoteControlSecurityIdentity LocalIdentity { get; }
    internal RemoteControlPairingMaterial LocalPairing { get; }
    internal void RequireCurrent() => _requireCurrent();
    public void Dispose() => Crypto.Dispose();
}
