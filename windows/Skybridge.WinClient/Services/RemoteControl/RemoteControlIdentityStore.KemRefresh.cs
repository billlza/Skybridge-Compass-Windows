using System.Collections.Immutable;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using Skybridge.WinClient.Services.Connection;

namespace Skybridge.WinClient.Services.RemoteControl;

public sealed partial class RemoteControlIdentityStore
{
    internal ProductPeerAuthentication PrepareUsbAuthentication(UsbControlRoute route, SignedKemRefreshLease refresh,
        RemoteControlViewerAccount account)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(refresh); ArgumentNullException.ThrowIfNull(account);
        lock (_gate)
        {
            ThrowIfDisposed(); refresh.RequireCurrent();
            var paired = _trusted.SingleOrDefault(p => p.DeviceId == route.PeerDeviceId && p.ProtocolPublicKeyFingerprint == route.Fingerprint)
                ?? throw new InvalidOperationException("USB authentication requires the selected saved identity.");
            var localIdentity = new RemoteControlSecurityIdentity(account.AccountDisplayName, account.NebulaId,
                PublicMaterial.DeviceId, PublicMaterial.DeviceName);
            localIdentity.Validate();
            var keys = refresh.ClaimKeys(paired.DeviceId, paired.ProtocolPublicKeyFingerprint, route.EndpointDigest);
            var legacy = keys.SingleOrDefault(k => k.SuiteWireId == 257)?.PublicKey.ToArray() ?? [];
            var q = keys.SingleOrDefault(k => k.SuiteWireId == 18)?.PublicKey.ToArray() ?? [];
            var soa = new RemoteControlHandshakeSoa(RemoteControlHandshakeBinding.PeerId(PublicMaterial.DeviceId),
                RemoteControlHandshakeBinding.PeerId(paired.DeviceId), RandomNumberGenerator.GetBytes(16));
            WebRtcProductPqcHandshakeCryptoProviderOptions options;
            if (q.Length != 0)
            {
                var policy = RequirePolicySession();
                if (policy.AuthProfile != refresh.QAuthProfile)
                    throw new InvalidOperationException("The Q policy changed after the signed USB key refresh.");
                options = new(_signingPrivateKey, legacy, ReadOnlyMemory<byte>.Empty, policy,
                    q, ReadOnlyMemory<byte>.Empty, soa.EncodeTlv(), WebRtcProductHandshakeCodec.SuiteQPeriaptPolicyBound);
            }
            else
            {
                if (legacy.Length == 0) throw new InvalidDataException("The signed refresh contains no usable native PQC suite.");
                options = new(_signingPrivateKey, legacy, initiatorExtensionsRaw: soa.EncodeTlv(),
                    initiatorSuiteWireId: WebRtcProductHandshakeCodec.SuiteMlKem768Mldsa65ForwardSecure);
            }
            // The prepared owner takes the native provider immediately. It must be
            // released even when the next cancellation/expiry check prevents dial.
            return new(route, new(paired.DeviceId, paired.ProtocolPublicKeyFingerprint),
                new WebRtcProductPqcHandshakeCryptoProvider(options), localIdentity, PublicMaterial, refresh.RequireCurrent);
        }
    }

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
