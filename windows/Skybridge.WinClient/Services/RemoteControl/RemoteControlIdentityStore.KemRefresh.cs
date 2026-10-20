using System.Collections.Immutable;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.RemoteControl;

public sealed partial class RemoteControlIdentityStore
{
    internal SignedLanKemRefreshInitiator CreateKemRefreshInitiator(string peerDeviceId, string fingerprint,
        Action requireCurrent, string osVersion)
    {
        lock (_gate)
        {
            ThrowIfDisposed(); requireCurrent();
            var canonical = RemoteControlHandshakeBinding.CanonicalDeviceId(peerDeviceId);
            RemoteControlPairingMaterial ReadPaired()
            {
                lock (_gate)
                {
                    ThrowIfDisposed(); requireCurrent();
                    return _trusted.SingleOrDefault(p => p.DeviceId == canonical && p.ProtocolPublicKeyFingerprint == fingerprint)
                        ?? throw new InvalidOperationException("Key refresh requires the exact already-paired protocol identity.");
                }
            }
            _ = ReadPaired();
            return new(CaptureKemRefreshInventory(osVersion), ReadPaired, VerifyPibSignature, requireCurrent);
        }
    }

    internal SignedLanKemRefreshResponder CreateKemRefreshResponder(Action requireCurrent, string osVersion)
    {
        lock (_gate)
        {
            ThrowIfDisposed(); requireCurrent();
            return new(CaptureKemRefreshInventory(osVersion), () => TrustedPeers, SignLanBootstrap, requireCurrent);
        }
    }

    // Both directions capture the actual inventory while the identity gate is held.
    private LanKemRefreshInventory CaptureKemRefreshInventory(string osVersion)
    {
        var material = PublicMaterial;
        return new(material.DeviceId, material.ProtocolPublicKey.ToArray().ToImmutableArray(),
            [new(0x0012, material.QPeriaptPublicKey.ToArray().ToImmutableArray()),
             new(0x0101, material.MlKem768PublicKey.ToArray().ToImmutableArray())],
            "windows", osVersion, RequirePolicySession().AuthProfile);
    }

    private ImmutableArray<byte> SignLanBootstrap(byte[] preimage)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var signer = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, _signingPrivateKey);
            ImmutableArray<byte> signature = default;
            Exception? failure = null;
            try { signature = signer.SignData(preimage).ToImmutableArray(); }
            catch (Exception error) { failure = error; }
            try { signer.Dispose(); }
            catch (Exception cleanup)
            {
                // The listener retains this owner and stops accepting on unconfirmed
                // release; neither the private key nor a detached signing task escapes.
                throw new LanResponderCryptoReleaseException(signer, failure is null ? cleanup : new AggregateException(failure, cleanup));
            }
            if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
            return signature;
        }
    }
}
