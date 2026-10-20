using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

/// <summary>One USB enrollment transaction using the existing PIB wire and
/// identity owner. Public discovery never grants trust. The commit port is
/// reached only after local approval and the peer's signed final acknowledgement.</summary>
internal sealed class ProductPibInitiator
{
    private readonly LanPibLocalIdentity _local;
    private readonly string _fingerprint;
    private readonly Func<byte[], ImmutableArray<byte>> _sign;
    private readonly Action<ImmutableArray<byte>, byte[], ImmutableArray<byte>> _verify;
    private readonly Action<RemoteControlPairingMaterial> _preflight;
    private readonly Func<RemoteControlPairingMaterial, Action, CancellationToken, Task> _commit;
    private readonly ILanPibApprovalPresenter _approval;
    private readonly Action _requireCurrent;
    private readonly TimeProvider _time;
    private int _started;

    internal ProductPibInitiator(LanPibLocalIdentity local, Func<byte[], ImmutableArray<byte>> sign,
        Action<ImmutableArray<byte>, byte[], ImmutableArray<byte>> verify,
        Action<RemoteControlPairingMaterial> preflight,
        Func<RemoteControlPairingMaterial, Action, CancellationToken, Task> commit,
        ILanPibApprovalPresenter approval, Action requireCurrent, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(local); ArgumentNullException.ThrowIfNull(sign);
        ArgumentNullException.ThrowIfNull(verify); ArgumentNullException.ThrowIfNull(preflight);
        ArgumentNullException.ThrowIfNull(commit); ArgumentNullException.ThrowIfNull(approval);
        ArgumentNullException.ThrowIfNull(requireCurrent);
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(local.DeviceId) != local.DeviceId)
            throw new InvalidDataException("PIB requires the canonical existing local identity.");
        _fingerprint = new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65,
            local.PublicKey.ToArray()).AuthoritativeFingerprint;
        _local = local; _sign = sign; _verify = verify; _preflight = preflight; _commit = commit;
        _approval = approval; _requireCurrent = requireCurrent; _time = time ?? TimeProvider.System;
    }

    internal async Task<RemoteControlPairingMaterial> PairUsbAsync(UsbPeerInspection target,
        Func<byte[], CancellationToken, Task<ReadOnlyMemory<byte>>> exchange, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(target); ArgumentNullException.ThrowIfNull(exchange);
        if (Interlocked.Exchange(ref _started, 1) != 0)
            throw new InvalidOperationException("A PIB initiator owns exactly one transaction.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromMinutes(5));
        try { return await RunAsync(target, exchange, deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
        { throw new TimeoutException("The pairing transaction exceeded its five-minute limit.", error); }
    }

    private async Task<RemoteControlPairingMaterial> RunAsync(UsbPeerInspection target,
        Func<byte[], CancellationToken, Task<ReadOnlyMemory<byte>>> exchange, CancellationToken current)
    {
        long start = _time.GetTimestamp(), lastWall = long.MinValue;
        var clockGate = new object();
        long Observe()
        {
            current.ThrowIfCancellationRequested(); _requireCurrent();
            lock (clockGate)
            {
                long wall = _time.GetUtcNow().ToUnixTimeMilliseconds();
                var elapsed = _time.GetElapsedTime(start);
                if (wall < lastWall || elapsed < TimeSpan.Zero || elapsed >= TimeSpan.FromMinutes(5))
                    throw new InvalidOperationException("The pairing clock or transaction lifetime is no longer valid.");
                lastWall = wall;
                return wall;
            }
        }
        var peer = target.Response.Identity;
        var admitted = Observe();
        UsbPeerDiscoveryWire.Validate(target.Response, target.Response.Request, DateTimeOffset.FromUnixTimeMilliseconds(admitted));
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(peer.DeviceID) == _local.DeviceId || peer.Fingerprint == _fingerprint)
            throw new LanPibRejectedException("selfPairing", "The local identity cannot enroll itself.");
        // Apple retains the local-control wire scope "lan" on USB. Its signed
        // endpoint digest binds the concrete cable route independently.
        var endpointDigest = Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes($"SkyBridge-USB|{target.Udid}|9527|{peer.DeviceID}")));
        var request = new LanPibRequest(3, Guid.NewGuid().ToString("D"), _local.DeviceId, peer.DeviceID,
            ["ML-DSA-65"], "ML-DSA-65", _local.PublicKey, _fingerprint, [],
            RandomNumberGenerator.GetBytes(32).ToImmutableArray(), ReferenceSeconds(admitted),
            BonjourEndpointDigest: endpointDigest);
        request = request with { RequesterSignature = _sign(LanPibCanonical.RequestPreimage(request)) };
        LanPibValidation.RequireRequestFreshness(request, Observe());
        ReadOnlyMemory<byte> reply;
        using (var candidateDeadline = CancellationTokenSource.CreateLinkedTokenSource(current))
        {
            candidateDeadline.CancelAfter(TimeSpan.FromSeconds(20));
            try
            {
                reply = await exchange(LanPibWire.EncodeRequest(request), candidateDeadline.Token).ConfigureAwait(false);
                candidateDeadline.Token.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException error) when (!current.IsCancellationRequested && candidateDeadline.IsCancellationRequested)
            { throw new TimeoutException("The peer did not return its pairing candidate within twenty seconds.", error); }
        }
        RejectRemoteFailure(reply.Span, request, Observe());
        var candidate = LanPibWire.DecodeCandidate(reply.Span);
        LanPibValidation.RequireCandidateBindings(request, candidate, peer.Fingerprint, Observe());
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(candidate.DeviceId) !=
            RemoteControlHandshakeBinding.CanonicalDeviceId(peer.DeviceID) || candidate.ProtocolSigningAlgorithm != peer.Algorithm ||
            !candidate.ProtocolIdentityPublicKey.AsSpan().SequenceEqual(peer.PublicKey.AsSpan()))
            throw new InvalidDataException("The pairing candidate changed the selected USB identity.");
        _verify(peer.PublicKey, LanPibCanonical.CandidatePreimage(candidate), candidate.Signature);
        var material = RemoteControlPairingMaterial.CreateProtocolIdentity(candidate.DeviceId,
            candidate.DeviceName ?? target.Response.Name, candidate.ProtocolIdentityPublicKey.AsSpan());
        _preflight(material);
        void RequireCandidate() =>
            LanPibValidation.RequireAdmittedCandidateCurrent(request, candidate, peer.Fingerprint, Observe());
        RequireCandidate();
        var approval = new LanPibApprovalRequest(request, candidate, LanPibCanonical.SasCode(request, candidate),
            RequireCandidate, LanPibApprovalRole.Initiator);
        if (!await _approval.ShowAsync(approval, current).ConfigureAwait(false))
            throw new LanPibRejectedException("localApprovalRejected", "The local device did not approve this pairing.");
        RequireCandidate();
        double sent = ReferenceSeconds(Observe());
        var confirm = new LanPibConfirm(3, request.TransactionId, request.RequesterDeviceId, candidate.DeviceId,
            request.RequesterProtocolIdentityFingerprint, candidate.ProtocolIdentityFingerprint, request.Nonce,
            LanPibCanonical.RequestHash(request), LanPibCanonical.CandidateHash(candidate),
            LanPibCanonical.SasTranscriptHash(request, candidate), RandomNumberGenerator.GetBytes(32).ToImmutableArray(),
            sent, Math.Min(candidate.ExpiresAt, sent + 300.0), []);
        confirm = confirm with { RequesterSignature = _sign(LanPibCanonical.ConfirmPreimage(confirm)) };
        LanPibValidation.RequireConfirmBindings(request, candidate, confirm, Observe());
        var finalReply = await exchange(LanPibWire.EncodeConfirm(confirm), current).ConfigureAwait(false);
        RejectRemoteFailure(finalReply.Span, request, Observe());
        var ack = LanPibWire.DecodeFinalAck(finalReply.Span);
        LanPibValidation.RequireFinalAckBindings(request, candidate, confirm, ack, Observe());
        _verify(peer.PublicKey, LanPibCanonical.FinalAckPreimage(ack), ack.ResponderSignature);
        void RequireCommit() =>
            LanPibValidation.RequireFinalAckBindings(request, candidate, confirm, ack, Observe());
        RequireCommit();
        await _commit(material, RequireCommit, current).ConfigureAwait(false);
        // The durable commit is the completion point. A later cancellation cannot
        // turn a committed trust record into an alleged rollback.
        return material;
    }

    private static double ReferenceSeconds(long milliseconds) => milliseconds / 1000.0 - 978307200.0;

    private static void RejectRemoteFailure(ReadOnlySpan<byte> reply, LanPibRequest request, long now)
    {
        if (LanBootstrapWire.ReadDiscriminator(reply) != "kemRefreshFailure") return;
        var failure = LanBootstrapWire.Decode<Failure>(reply, "kemRefreshFailure");
        long sent = LanBootstrapCanonical.Milliseconds(failure.SentAt);
        if (failure.Version != 1 || failure.RequesterDeviceId != request.RequesterDeviceId ||
            failure.TargetDeviceId != request.TargetDeviceId ||
            failure.RequestHashHex is { } hash && hash != LanPibCanonical.RequestHash(request) ||
            failure.Stage.Length is < 1 or > 64 || failure.ReasonCode.Length is < 1 or > 64 ||
            failure.ReasonCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_') ||
            Encoding.UTF8.GetByteCount(failure.Reason) > 1024 ||
            (decimal)sent - now > 30_000 || (decimal)now - sent > 120_000)
            throw new InvalidDataException("The peer rejection has an invalid transaction binding.");
        // This unsigned diagnostic only explains failure; it cannot grant trust,
        // choose a weaker suite, or authorize a retry.
        throw new LanPibRejectedException("remote_" + failure.ReasonCode, "The peer rejected the pairing exchange.");
    }

    private sealed record Failure(int Version, string RequesterDeviceId, string TargetDeviceId,
        string Stage, string ReasonCode, string Reason, double SentAt, string? RequestHashHex = null);
}
