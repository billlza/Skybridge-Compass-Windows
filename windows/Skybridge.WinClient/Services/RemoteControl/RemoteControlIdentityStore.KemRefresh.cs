using System.Collections.Immutable;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.RemoteControl;

public sealed partial class RemoteControlIdentityStore
{
    internal SignedLanKemRefreshResponder CreateKemRefreshResponder(Action requireCurrent, string osVersion)
    {
        lock (_gate)
        {
            ThrowIfDisposed(); requireCurrent();
            var material = PublicMaterial;
            var inventory = new LanKemRefreshInventory(material.DeviceId, material.ProtocolPublicKey.ToArray().ToImmutableArray(),
                [new(0x0012, material.QPeriaptPublicKey.ToArray().ToImmutableArray()),
                 new(0x0101, material.MlKem768PublicKey.ToArray().ToImmutableArray())],
                "windows", osVersion, RequirePolicySession().AuthProfile);
            return new(inventory, () => TrustedPeers, SignLanBootstrap, requireCurrent);
        }
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
