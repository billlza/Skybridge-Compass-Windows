using System.Collections.Immutable;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Skybridge.WinClient.Services.RemoteControl;

public sealed partial class RemoteControlIdentityStore
{
    // Discovery identifies a candidate and a route. Only the two signed decisions
    // authorize the initial signer. Later connections fetch fresh signed KEM material.
    internal async Task<RemoteControlPairingMaterial> PrepareLanFilePeerAsync(string deviceId, string fingerprint, DiscoveryPeerEndpoint route,
        Func<string, string, CancellationToken, Task<bool>> compare, Action requireCurrent, CancellationToken token)
    {
        if (route.Service != SkyBridgeProtocolConstants.TcpControlDnsSdService || route.Provenance != "resolved-dns-sd-endpoint" ||
            route.Port == 0 || string.IsNullOrWhiteSpace(route.HostName)) throw new InvalidDataException("Select a resolved local file device.");
        var id = RemoteControlHandshakeBinding.CanonicalDeviceId(deviceId);
        RemoteControlPairingMaterial? peer;
        string authProfile;
        lock (_gate)
        {
            ThrowIfDisposed(); requireCurrent(); token.ThrowIfCancellationRequested();
            CheckKnownSigner(id, fingerprint);
            peer = _trusted.SingleOrDefault(p => p.DeviceId == id) ?? _filePaired.SingleOrDefault(p => p.DeviceId == id);
            if (peer != null && !peer.IsProtocolIdentityOnly) return peer;
            authProfile = RequirePolicySession().AuthProfile;
        }
        if (peer is null)
        {
            using var transaction = CancellationTokenSource.CreateLinkedTokenSource(token);
            transaction.CancelAfter(TimeSpan.FromMinutes(5));
            peer = await PairSignerAsync(deviceId, fingerprint, route, compare, requireCurrent, transaction.Token).ConfigureAwait(false);
        }
        requireCurrent(); token.ThrowIfCancellationRequested();
        var refresh = new LanKemRefreshRequest(PublicMaterial.DeviceId, deviceId, [0x0012, 0x0101], SignedLanKemRefreshCanonical.PolicyHash(3),
            Nonce(), Now(), Version: 3, RequesterProtocolIdentityFingerprint: PublicMaterial.ProtocolPublicKeyFingerprint,
            TargetProtocolIdentityFingerprint: fingerprint, Platform: "windows", OsVersion: QPeriaptPeerPlatform.LocalVersion(), QPeriaptAuthProfile: authProfile);
        var wire = await ExchangeBootstrapAsync(route, SignedLanKemRefreshWire.EncodeRequest(refresh), TimeSpan.FromSeconds(15), token).ConfigureAwait(false);
        var response = SignedLanKemRefreshWire.DecodeResponse(wire.Span);
        SignedLanKemRefreshCanonical.RequireResponseBindings(refresh, response, fingerprint, Wall());
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(response.DeviceId) != id ||
            (!response.Aliases.IsDefault && response.Aliases.Any(alias => RemoteControlHandshakeBinding.CanonicalDeviceId(alias) != id)) ||
            response.ProtocolSigningAlgorithm != peer.ProtocolSigningAlgorithm || !response.ProtocolIdentityPublicKey.AsSpan().SequenceEqual(peer.ProtocolPublicKey.Span))
            throw new InvalidDataException("The signed KEM refresh changed the paired identity.");
        VerifyPibSignature(response.ProtocolIdentityPublicKey, SignedLanKemRefreshCanonical.ResponsePreimage(response), response.Signature);
        requireCurrent(); token.ThrowIfCancellationRequested();
        var ml = response.KemPublicKeys.SingleOrDefault(k => k.SuiteWireId == 0x0101);
        var q = response.KemPublicKeys.SingleOrDefault(k => k.SuiteWireId == 0x0012);
        if (q == null && ml == null) throw new InvalidDataException("The signed response contains no compatible PQC key.");
        var material = RemoteControlPairingMaterial.CreatePolicyBound(id, peer.DeviceName, peer.ProtocolPublicKey.Span,
            ml?.PublicKey.ToArray() ?? [], q?.PublicKey.ToArray() ?? []);
        // Network keys are session inputs, never a new identity, controller or file grant.
        lock (_gate)
        {
            ThrowIfDisposed(); CheckKnownSigner(id, fingerprint);
            if (!_trusted.Concat(_filePaired).Any(p => p.HasSameProtocolIdentity(material)))
                throw new InvalidDataException("The file pairing ended during KEM refresh.");
        }
        return material;
    }

    private async Task<RemoteControlPairingMaterial> PairSignerAsync(string deviceId, string fingerprint, DiscoveryPeerEndpoint route,
        Func<string, string, CancellationToken, Task<bool>> compare, Action requireCurrent, CancellationToken token)
    {
        var request = new LanPibRequest(3, Guid.NewGuid().ToString("D"), PublicMaterial.DeviceId, deviceId, ["ML-DSA-65"],
            PublicMaterial.ProtocolSigningAlgorithm, PublicMaterial.ProtocolPublicKey.ToArray().ToImmutableArray(),
            PublicMaterial.ProtocolPublicKeyFingerprint, [], Nonce(), Now());
        request = request with { RequesterSignature = SignLanBootstrap(LanPibCanonical.RequestPreimage(request)) };
        var wire = await ExchangeBootstrapAsync(route, LanPibWire.EncodeRequest(request), TimeSpan.FromSeconds(15), token).ConfigureAwait(false);
        var candidate = LanPibWire.DecodeCandidate(wire.Span);
        LanPibValidation.RequireCandidateBindings(request, candidate, fingerprint, Wall());
        var id = RemoteControlHandshakeBinding.CanonicalDeviceId(deviceId);
        if (candidate.ProtocolSigningAlgorithm != "ML-DSA-65" || RemoteControlHandshakeBinding.CanonicalDeviceId(candidate.DeviceId) != id)
            throw new InvalidDataException("The pairing candidate changed the selected device.");
        VerifyPibSignature(candidate.ProtocolIdentityPublicKey, LanPibCanonical.CandidatePreimage(candidate), candidate.Signature);
        var identity = RemoteControlPairingMaterial.CreateProtocolIdentity(id, candidate.DeviceName ?? candidate.DeviceId, candidate.ProtocolIdentityPublicKey.AsSpan());
        requireCurrent(); token.ThrowIfCancellationRequested();
        if (!await compare(identity.DeviceName, LanPibCanonical.SasCode(request, candidate), token).ConfigureAwait(false))
            throw new IOException("Pairing declined. The six digits must match on both devices.");
        requireCurrent(); token.ThrowIfCancellationRequested();
        var now = Now();
        var confirm = new LanPibConfirm(3, request.TransactionId, request.RequesterDeviceId, candidate.DeviceId,
            request.RequesterProtocolIdentityFingerprint, fingerprint, request.Nonce, LanPibCanonical.RequestHash(request),
            LanPibCanonical.CandidateHash(candidate), LanPibCanonical.SasTranscriptHash(request, candidate), Nonce(), now,
            Math.Min(now + 180, candidate.ExpiresAt), []);
        confirm = confirm with { RequesterSignature = SignLanBootstrap(LanPibCanonical.ConfirmPreimage(confirm)) };
        LanPibValidation.RequireConfirmBindings(request, candidate, confirm, Wall());
        var ackWire = await ExchangeBootstrapAsync(route, LanPibWire.EncodeConfirm(confirm), TimeSpan.FromSeconds(180), token).ConfigureAwait(false);
        var ack = LanPibWire.DecodeFinalAck(ackWire.Span);
        void AdmitCommit()
        {
            token.ThrowIfCancellationRequested(); requireCurrent();
            LanPibValidation.RequireFinalAckBindings(request, candidate, confirm, ack, Wall());
        }
        AdmitCommit();
        VerifyPibSignature(candidate.ProtocolIdentityPublicKey, LanPibCanonical.FinalAckPreimage(ack), ack.ResponderSignature);
        RememberLanFilePeer(identity, AdmitCommit, token);
        return identity;
    }

    private static double Now() => LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow);
    private static long Wall() => LanPibCanonical.Milliseconds(Now());
    private static ImmutableArray<byte> Nonce() => RandomNumberGenerator.GetBytes(24).ToImmutableArray();

    private static async Task<ReadOnlyMemory<byte>> ExchangeBootstrapAsync(DiscoveryPeerEndpoint route, byte[] message, TimeSpan timeout, CancellationToken token)
    {
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
        waiting.CancelAfter(timeout);
        using var client = new TcpClient();
        try
        {
            using var connecting = CancellationTokenSource.CreateLinkedTokenSource(waiting.Token);
            connecting.CancelAfter(TimeSpan.FromSeconds(8));
            await client.ConnectAsync(route.HostName, route.Port, connecting.Token).ConfigureAwait(false);
            await using var wire = new TcpProductControlTransport(client, LanBootstrapWire.MaximumBytes, LanBootstrapWire.MaximumBytes);
            await wire.SendAsync(message, waiting.Token).ConfigureAwait(false);
            var response = await wire.ReadAsync(waiting.Token).ConfigureAwait(false);
            if (LanBootstrapWire.ReadDiscriminator(response.Span) is "protocolIdentityBindingFailure" or "kemRefreshFailure")
                throw new IOException("The device declined or could not verify pairing.");
            return response;
        }
        catch (OperationCanceledException e) when (!token.IsCancellationRequested) { throw new TimeoutException("The LAN pairing operation timed out.", e); }
    }
}
