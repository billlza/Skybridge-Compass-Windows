using System.Collections.Immutable;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.RemoteControl;

public sealed partial class RemoteControlIdentityStore
{
    internal LanPibResponder CreatePibResponder(ILanPibApprovalPresenter approval, Action requireCurrent, bool filesOnly = false)
    {
        lock (_gate)
        {
            ThrowIfDisposed(); requireCurrent();
            var material = PublicMaterial;
            return new(new(material.DeviceId, material.DeviceName, material.ProtocolPublicKey.ToArray().ToImmutableArray()),
                SignLanBootstrap, VerifyPibSignature, peer => PreflightPibIdentity(peer, filesOnly),
                async (peer, requireCommit, token) =>
                {
                    if (filesOnly) { RememberLanFilePeer(peer, requireCommit, token); return; }
                    await ImportApprovedPibPeerAsync(peer, requireCommit, token).ConfigureAwait(false);
                }, approval, requireCurrent);
        }
    }
    internal IReadOnlyCollection<RemoteControlTrustedPeer> FileTransferPeers
    {
        get
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                return _trusted.Concat(_filePaired).DistinctBy(p => p.DeviceId)
                    .Select(p => new RemoteControlTrustedPeer(p.DeviceId, p.ProtocolPublicKeyFingerprint)).ToArray();
            }
        }
    }

    private void RequireLanPeerCapacity(RemoteControlPairingMaterial candidate)
    {
        var ids = _trusted.Concat(_filePaired).Select(peer => peer.DeviceId).ToHashSet(StringComparer.Ordinal);
        if (!ids.Contains(candidate.DeviceId) && ids.Count >= MaximumTrustedPeers)
            throw new InvalidOperationException("The paired LAN device limit is reached.");
    }

    private void RememberLanFilePeer(RemoteControlPairingMaterial peer, Action requireCommit, CancellationToken token)
    {
        lock (_gate)
        {
            ThrowIfDisposed(); requireCommit(); token.ThrowIfCancellationRequested();
            if (!peer.IsProtocolIdentityOnly) throw new InvalidDataException("PIB authorizes only its verified signing identity.");
            CheckKnownSigner(peer.DeviceId, peer.ProtocolPublicKeyFingerprint);
            if (!CheckImport(peer, PublicMaterial, _filePaired)) return;
            RequireLanPeerCapacity(peer);
            var replacement = new List<RemoteControlPairingMaterial>(_filePaired) { peer };
            Persist(_trusted, token, requireCommit, filePeers: replacement);
            _filePaired.Add(peer);
        }
    }

    private void PreflightPibIdentity(RemoteControlPairingMaterial material, bool filesOnly)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            CheckKnownSigner(material.DeviceId, material.ProtocolPublicKeyFingerprint);
            RequireLanPeerCapacity(material);
            var members = filesOnly ? _filePaired : _trusted;
            if (CheckImport(material, PublicMaterial, members) && members.Count >= MaximumTrustedPeers)
                throw new InvalidOperationException("The trusted peer limit is reached.");
        }
    }
    internal static void VerifyPibSignature(ImmutableArray<byte> key, byte[] preimage, ImmutableArray<byte> signature)
    {
        var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, key.AsSpan());
        Exception? failure = null;
        try
        {
            if (!verifier.VerifyData(preimage, signature.AsSpan()))
                throw new LanPibRejectedException("signatureInvalid", "The requester did not prove possession of its ML-DSA-65 identity.");
        }
        catch (Exception error) { failure = error; }
        try { verifier.Dispose(); }
        catch (Exception cleanup)
        {
            throw new LanResponderCryptoReleaseException(verifier,
                failure is null ? cleanup : new AggregateException(failure, cleanup));
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
