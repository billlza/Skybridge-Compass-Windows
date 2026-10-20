using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services.Connection;

internal static class UsbPeerPairingMatcher
{
    internal static UsbPeerPairingState Match(UsbPeerInspection inspection, string localDeviceId,
        IReadOnlyList<RemoteControlPairingMaterial> trusted)
    {
        var identity = inspection.Response.Identity;
        var deviceId = RemoteControlHandshakeBinding.CanonicalDeviceId(identity.DeviceID);
        if (deviceId == RemoteControlHandshakeBinding.CanonicalDeviceId(localDeviceId))
            return UsbPeerPairingState.IdentityConflict;
        var saved = trusted.SingleOrDefault(peer => peer.DeviceId == deviceId);
        if (saved is null) return UsbPeerPairingState.Unpaired;
        return saved.ProtocolSigningAlgorithm == identity.Algorithm &&
            saved.ProtocolPublicKeyFingerprint == identity.Fingerprint &&
            saved.ProtocolPublicKey.Span.SequenceEqual(identity.PublicKey.AsSpan())
            ? UsbPeerPairingState.Paired : UsbPeerPairingState.IdentityConflict;
    }
}
