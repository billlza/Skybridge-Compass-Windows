using System.Collections.Immutable;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.RemoteControl;

public sealed partial class RemoteControlIdentityStore
{
    internal LanPibResponder CreatePibResponder(ILanPibApprovalPresenter approval, Action requireCurrent)
    {
        lock (_gate)
        {
            ThrowIfDisposed(); requireCurrent();
            var material = PublicMaterial;
            return new(new(material.DeviceId, material.DeviceName, material.ProtocolPublicKey.ToArray().ToImmutableArray()),
                SignLanBootstrap, VerifyPibSignature, PreflightPibIdentity,
                async (peer, requireCommit, token) =>
                {
                    await ImportApprovedPibPeerAsync(peer, requireCommit, token).ConfigureAwait(false);
                }, approval, requireCurrent);
        }
    }
    private void PreflightPibIdentity(RemoteControlPairingMaterial material)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (CheckImport(material) && _trusted.Count >= MaximumTrustedPeers)
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
