namespace Skybridge.WinClient.Services.Audio;

/// <summary>Historical identity evidence for one MAIN owner. This is not an account grant,
/// playback permission, or proof that the owner remains live.</summary>
internal sealed class AudioSessionIdentityBinding
{
    private AudioSessionIdentityBinding(ProductSessionKeys keys, string localDeviceId, string peerDeviceId,
        ProductHandshakeProtocolIdentity localIdentity, ProductHandshakeProtocolIdentity peerIdentity,
        RemoteControlHandshakeSoa soa)
    {
        SessionId = keys.SessionId;
        Role = keys.Role;
        LocalDeviceId = localDeviceId;
        PeerDeviceId = peerDeviceId;
        LocalProtocolIdentity = localIdentity;
        PeerProtocolIdentity = peerIdentity;
        AttemptId = Convert.ToHexStringLower(soa.AttemptId.Span);
    }

    internal string SessionId { get; }
    internal ProductHandshakeRole Role { get; }
    internal string LocalDeviceId { get; }
    internal string PeerDeviceId { get; }
    internal ProductHandshakeProtocolIdentity LocalProtocolIdentity { get; }
    internal ProductHandshakeProtocolIdentity PeerProtocolIdentity { get; }
    internal string AttemptId { get; }

    internal static AudioSessionIdentityBinding Capture(ProductSessionKeys keys, string localDeviceId,
        string peerDeviceId, ProductHandshakeProtocolIdentity localIdentity,
        ProductHandshakeProtocolIdentity peerIdentity, ReadOnlySpan<byte> initiatorExtensions)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(peerIdentity);
        // Account registration preserves the exact device-ID spelling. SOA comparisons below
        // canonicalize only the hash input; never replace the authenticated declaration with an alias.
        var localId = CurrentPathProtocolIdentityBinding.NormalizeDeviceId(localDeviceId);
        var peerId = CurrentPathProtocolIdentityBinding.NormalizeDeviceId(peerDeviceId);
        if (localId != localDeviceId || peerId != peerDeviceId)
            throw new InvalidDataException("Audio account identities require exact device-ID declarations.");
        var soa = RemoteControlHandshakeSoa.RequireFromExtensions(initiatorExtensions);
        var (initiatorId, targetId) = keys.Role switch
        {
            ProductHandshakeRole.Initiator => (localId, peerId),
            ProductHandshakeRole.Responder => (peerId, localId),
            _ => throw new InvalidDataException("Audio requires a known handshake role.")
        };
        if (!soa.InitiatorPeerId.Span.SequenceEqual(RemoteControlHandshakeBinding.PeerId(initiatorId)) ||
            !soa.TargetPeerId.Span.SequenceEqual(RemoteControlHandshakeBinding.PeerId(targetId)))
            throw new InvalidDataException("Audio SOA does not bind the exact local and peer device IDs for this MAIN session.");
        return new(keys, localId, peerId, localIdentity, peerIdentity, soa);
    }
}
