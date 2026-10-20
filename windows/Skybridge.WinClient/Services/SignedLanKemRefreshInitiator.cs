using System.Collections.Immutable;
using System.Security.Cryptography;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

/// <summary>Fresh public KEM material for one already-paired USB identity. This
/// exchange neither changes persistent trust nor grants account/session authority.</summary>
internal sealed class SignedLanKemRefreshInitiator
{
    private readonly LanKemRefreshInventory _local;
    private readonly Func<RemoteControlPairingMaterial> _readPaired;
    private readonly Action<ImmutableArray<byte>, byte[], ImmutableArray<byte>> _verify;
    private readonly Action _requireCurrent;
    private readonly TimeProvider _time;
    private readonly TimeSpan _timeout;
    private readonly string _fingerprint;
    private int _started;

    internal SignedLanKemRefreshInitiator(LanKemRefreshInventory local,
        Func<RemoteControlPairingMaterial> readPaired,
        Action<ImmutableArray<byte>, byte[], ImmutableArray<byte>> verify,
        Action requireCurrent, TimeProvider? time = null, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(local); ArgumentNullException.ThrowIfNull(readPaired);
        ArgumentNullException.ThrowIfNull(verify); ArgumentNullException.ThrowIfNull(requireCurrent);
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(local.DeviceId) != local.DeviceId ||
            local.Keys.IsDefault || local.Keys.Any(k => k is null) ||
            !local.Keys.Select(k => k.SuiteWireId).Order().SequenceEqual(new[] { 18, 257 }))
            throw new InvalidDataException("Windows SKR initiation requires its actual Q and ML-KEM inventory.");
        foreach (var key in local.Keys) SignedLanKemRefreshCanonical.RequireKey(key);
        _fingerprint = new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65,
            local.SigningPublicKey.ToArray()).AuthoritativeFingerprint;
        SignedLanKemRefreshCanonical.RequireCapabilities([18, 257], local.Platform, local.OsVersion, local.QAuthProfile, true);
        _local = local; _readPaired = readPaired; _verify = verify; _requireCurrent = requireCurrent;
        _time = time ?? TimeProvider.System; _timeout = timeout ?? TimeSpan.FromSeconds(20);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromSeconds(20)) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    internal async Task<SignedKemRefreshLease> RefreshUsbAsync(UsbPeerInspection selected,
        Func<byte[], CancellationToken, Task<ReadOnlyMemory<byte>>> exchange, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(selected); ArgumentNullException.ThrowIfNull(exchange);
        if (Interlocked.Exchange(ref _started, 1) != 0) throw new InvalidOperationException("SKR initiation is single-use.");
        var clock = new RefreshClock(_time);
        void RequireAuthority()
        {
            token.ThrowIfCancellationRequested(); _requireCurrent();
            var paired = _readPaired() ?? throw new InvalidOperationException("The saved peer authority is unavailable.");
            var peer = selected.Response.Identity;
            if (paired.DeviceId != RemoteControlHandshakeBinding.CanonicalDeviceId(peer.DeviceID) ||
                paired.ProtocolSigningAlgorithm != peer.Algorithm || paired.ProtocolPublicKeyFingerprint != peer.Fingerprint ||
                !paired.ProtocolPublicKey.Span.SequenceEqual(peer.PublicKey.AsSpan()) || paired.DeviceId == _local.DeviceId ||
                paired.ProtocolPublicKeyFingerprint == _fingerprint)
                throw new InvalidDataException("USB key refresh no longer matches the exact saved protocol identity.");
        }
        RequireAuthority();
        long now = clock.Observe();
        UsbPeerDiscoveryWire.Validate(selected.Response, selected.Response.Request, DateTimeOffset.FromUnixTimeMilliseconds(now));
        var request = new LanKemRefreshRequest(_local.DeviceId, selected.Response.Identity.DeviceID,
            [18, 257], SignedLanKemRefreshCanonical.PolicyHash(3), RandomNumberGenerator.GetBytes(32).ToImmutableArray(),
            now / 1000.0 - 978307200.0, Version: 3,
            RequesterProtocolIdentityFingerprint: _fingerprint,
            TargetProtocolIdentityFingerprint: selected.Response.Identity.Fingerprint,
            BonjourEndpointDigest: selected.EndpointDigest, Platform: _local.Platform,
            OsVersion: _local.OsVersion, QPeriaptAuthProfile: _local.QAuthProfile);
        ReadOnlyMemory<byte> reply;
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            deadline.CancelAfter(_timeout);
            try
            {
                reply = await exchange(SignedLanKemRefreshWire.EncodeRequest(request), deadline.Token).ConfigureAwait(false);
                deadline.Token.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
            { throw new TimeoutException("USB key refresh exceeded its bounded response deadline.", error); }
        }
        RequireAuthority(); now = clock.Observe();
        if (clock.Elapsed >= _timeout) throw new TimeoutException("USB key refresh completed after its response deadline.");
        RejectRemoteFailure(reply.Span, request, now);
        var response = SignedLanKemRefreshWire.DecodeResponse(reply.Span);
        SignedLanKemRefreshCanonical.RequireResponseBindings(request, response, selected.Response.Identity.Fingerprint, now);
        // The canonical device ID and exact saved public key are authoritative.
        // Signed aliases cannot replace the selected device or add trusted IDs.
        if (RemoteControlHandshakeBinding.CanonicalDeviceId(response.DeviceId) !=
                RemoteControlHandshakeBinding.CanonicalDeviceId(selected.Response.Identity.DeviceID) ||
            response.ProtocolSigningAlgorithm != selected.Response.Identity.Algorithm ||
            !response.ProtocolIdentityPublicKey.AsSpan().SequenceEqual(selected.Response.Identity.PublicKey.AsSpan()))
            throw new InvalidDataException("SKR response changed the selected signer or device.");
        _verify(selected.Response.Identity.PublicKey, SignedLanKemRefreshCanonical.ResponsePreimage(response), response.Signature);
        RequireAuthority(); now = clock.Observe();
        if (clock.Elapsed >= _timeout) throw new TimeoutException("USB key refresh verification exceeded its response deadline.");
        SignedLanKemRefreshCanonical.RequireResponseBindings(request, response, selected.Response.Identity.Fingerprint, now);
        if (response.KemPublicKeys.IsEmpty) throw new LanKemRefreshRejectedException("noCommonSuite", "The paired devices have no permitted common KEM suite.");
        return new(request, response, clock, RequireAuthority);
    }

    private static void RejectRemoteFailure(ReadOnlySpan<byte> reply, LanKemRefreshRequest request, long now)
    {
        if (LanBootstrapWire.ReadDiscriminator(reply) != "kemRefreshFailure") return;
        var failure = LanBootstrapWire.Decode<Failure>(reply, "kemRefreshFailure");
        long sent = LanBootstrapCanonical.Milliseconds(failure.SentAt);
        if (failure.Version != 1 || failure.RequesterDeviceId != request.RequesterDeviceId || failure.TargetDeviceId != request.TargetDeviceId ||
            failure.RequestHashHex != SignedLanKemRefreshCanonical.RequestHash(request) || failure.Stage != "kem_refresh" ||
            failure.ReasonCode.Length is < 1 or > 64 || failure.ReasonCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '_') ||
            System.Text.Encoding.UTF8.GetByteCount(failure.Reason) > 1024 || (decimal)sent - now > 30_000 || (decimal)now - sent > 120_000)
            throw new InvalidDataException("SKR diagnostic does not match the current request.");
        throw new LanKemRefreshRejectedException("remote_" + failure.ReasonCode, "The peer rejected key refresh.");
    }
    private sealed record Failure(int Version, string RequesterDeviceId, string TargetDeviceId,
        string Stage, string ReasonCode, string Reason, double SentAt, string? RequestHashHex = null);

    internal sealed class RefreshClock(TimeProvider time)
    {
        private readonly object _gate = new();
        private readonly long _started = time.GetTimestamp();
        private long _lastWall = long.MinValue;
        private TimeSpan _lastElapsed;
        internal TimeSpan Elapsed => time.GetElapsedTime(_started);
        internal long Observe()
        {
            lock (_gate)
            {
                long now = time.GetUtcNow().ToUnixTimeMilliseconds();
                var elapsed = Elapsed;
                if (now < 0 || now < _lastWall || elapsed < _lastElapsed || elapsed >= TimeSpan.FromMinutes(5))
                    throw new InvalidOperationException("SKR clock or maximum elapsed lifetime is no longer valid.");
                _lastWall = now; _lastElapsed = elapsed; return now;
            }
        }
    }
}

/// <summary>Verified public keys retained only for one prepared initiator. Never
/// serialized as pairing material. Every use rechecks time, account and saved pin.</summary>
internal sealed class SignedKemRefreshLease
{
    private readonly LanSignedKemRefresh _response;
    private readonly SignedLanKemRefreshInitiator.RefreshClock _clock;
    private readonly Action _requireAuthority;
    private int _claimed;
    internal string PeerDeviceId { get; }
    internal string Fingerprint { get; }
    internal string EndpointDigest { get; }
    internal string? QAuthProfile => _response.QPeriaptAuthProfile;
    internal long ExpiresAtMilliseconds { get; }

    internal SignedKemRefreshLease(LanKemRefreshRequest request, LanSignedKemRefresh response,
        SignedLanKemRefreshInitiator.RefreshClock clock, Action requireAuthority)
    {
        _response = response; _clock = clock; _requireAuthority = requireAuthority;
        PeerDeviceId = RemoteControlHandshakeBinding.CanonicalDeviceId(response.DeviceId);
        Fingerprint = response.ProtocolIdentityFingerprint.Trim().ToLowerInvariant();
        EndpointDigest = request.BonjourEndpointDigest ?? throw new InvalidDataException("USB SKR lease has no route binding.");
        ExpiresAtMilliseconds = SignedLanKemRefreshCanonical.Milliseconds(response.ExpiresAt);
    }
    internal void RequireCurrent()
    {
        _requireAuthority();
        if (_clock.Observe() >= ExpiresAtMilliseconds) throw new InvalidOperationException("The signed KEM refresh has expired.");
    }
    internal ImmutableArray<LanKemRefreshPublicKey> ClaimKeys(string peerDeviceId, string fingerprint, string endpointDigest)
    {
        RequireCurrent();
        if (peerDeviceId != PeerDeviceId || fingerprint != Fingerprint || endpointDigest != EndpointDigest)
            throw new InvalidDataException("KEM lease cannot be used for another peer or carrier route.");
        if (Interlocked.Exchange(ref _claimed, 1) != 0)
            throw new InvalidOperationException("The refreshed keys already belong to a prepared initiator.");
        return _response.KemPublicKeys;
    }
}
