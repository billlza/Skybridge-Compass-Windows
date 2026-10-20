using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

internal static class ProductPibInitiatorTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases
    {
        get
        {
            var result = new List<(string, Func<Task>)>
            {
                ("PIB initiator binds USB route and peer identity across two real framed connections", RoundTrip),
                ("PIB initiator requires both approvals and the remote ACK before local commit", ApprovalOrder),
                ("PIB initiator refuses changed candidate identity signatures and final ACK bindings", Tampering),
                ("PIB initiator never sends confirmation after local refusal or authority revocation", RefusalAndRevocation),
                ("PIB initiator retains a canceled noncooperative approval until actual return", Cancellation),
                ("PIB initiator permits three-minute SAS comparison within the admitted candidate", LateApproval),
                ("PIB initiator rejects expired rolled-back and stalled-clock transactions", ClockLimits),
                ("PIB initiator preserves persistence failure and the durable commit cancellation boundary", CommitBoundary),
                ("PIB initiator rejects stale discovery and same local identity before exchange", DiscoveryAdmission),
                ("PIB initiator treats remote diagnostics only as a bound failure", RemoteFailure)
            };
            result.AddRange(ProductBootstrapExchangeTests.Cases);
            if (OperatingSystem.IsWindows())
            {
                if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041))
                    throw new PlatformNotSupportedException("USB enrollment requires the product's minimum Windows build 19041.");
                result.Add(("Windows PIB initiator verifies native signatures and reloads the committed DPAPI identity pin", NativePersistence));
                result.AddRange(UsbEnrollmentWorkspaceTests.Cases);
                result.AddRange(UsbControlWorkspaceTests.Cases);
            }
            return result;
        }
    }

    private const string LocalId = "id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string PeerId = "11111111-2222-3333-4444-555555555555";
    private const string Udid = "00008132-1111111111111111";
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
        private long _stamp;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _stamp;
        internal void Advance(double seconds, bool wall = true)
        { _stamp += TimeSpan.FromSeconds(seconds).Ticks; if (wall) Now += TimeSpan.FromSeconds(seconds); }
    }
    private sealed class Approval(Func<LanPibApprovalRequest, CancellationToken, Task<bool>> show) : ILanPibApprovalPresenter
    {
        public Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token) => show(request, token);
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly Clock Clock = new();
        internal readonly ImmutableArray<byte> LocalKey, PeerKey;
        private readonly MLDsa? _localNative, _peerNative;
        private readonly TimeProvider _time;
        internal readonly LanPibResponder Responder;
        internal bool Current = true;
        internal int Exchanges, LocalApprovals, PeerApprovals, LocalCommits, PeerCommits;
        internal LanPibRequest? Request;
        internal LanPibConfirm? Confirm;
        internal Func<LanPibApprovalRequest, CancellationToken, Task<bool>>? Show;
        internal Func<Action, CancellationToken, Task>? Persist;
        internal Func<LanPibCandidate, LanPibCandidate>? ChangeCandidate;
        internal Func<LanPibFinalAck, LanPibFinalAck>? ChangeAck;
        internal string? LocalSas, PeerSas;

        internal Fixture(bool native = false)
        {
            _time = native ? TimeProvider.System : Clock;
            if (native)
            {
                if (!MLDsa.IsSupported) throw new PlatformNotSupportedException("Native Windows ML-DSA is required.");
                _localNative = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                _peerNative = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            }
            LocalKey = _localNative?.ExportMLDsaPublicKey().ToImmutableArray()
                ?? Enumerable.Repeat((byte)19, 1952).ToImmutableArray();
            PeerKey = _peerNative?.ExportMLDsaPublicKey().ToImmutableArray()
                ?? Enumerable.Repeat((byte)37, 1952).ToImmutableArray();
            Responder = new(new("id:" + PeerId, "USB peer", PeerKey), SignPeer, Verify,
                _ => { }, (_, guard, _) =>
                {
                    guard(); PeerCommits++; return Task.CompletedTask;
                }, new Approval((request, _) =>
                {
                    request.RequireCurrent(); PeerApprovals++; PeerSas = request.SasCode;
                    Require(request.Role == LanPibApprovalRole.Responder && request.PeerDeviceId == request.Request.RequesterDeviceId,
                        "Responder approval presented its own identity.");
                    return Task.FromResult(true);
                }), RequireCurrent, _time);
        }
        // Controlled SHA ports exercise transaction state on non-Windows hosts;
        // they are not PQC verification. The Windows case below uses native ML-DSA.
        private static ImmutableArray<byte> ControlledSignature(ImmutableArray<byte> key, byte[] preimage) =>
            SHA256.HashData(key.Concat(preimage).ToArray()).ToImmutableArray();
        internal ImmutableArray<byte> SignPeer(byte[] data) =>
            _peerNative?.SignData(data).ToImmutableArray() ?? ControlledSignature(PeerKey, data);
        private ImmutableArray<byte> SignLocal(byte[] data) =>
            _localNative?.SignData(data).ToImmutableArray() ?? ControlledSignature(LocalKey, data);
        internal void Verify(ImmutableArray<byte> key, byte[] data, ImmutableArray<byte> signature)
        {
            if (_peerNative is not null) { RemoteControlIdentityStore.VerifyPibSignature(key, data, signature); return; }
            if (!signature.AsSpan().SequenceEqual(ControlledSignature(key, data).AsSpan()))
                throw new LanPibRejectedException("signatureInvalid", "Controlled fixture signature differs.");
        }
        internal void RequireCurrent()
        { if (!Current) throw new InvalidOperationException("The fixture authority was revoked."); }
        internal ILanPibApprovalPresenter Presenter => new Approval((request, token) =>
        {
            request.RequireCurrent(); LocalApprovals++; LocalSas = request.SasCode;
            Require(request.Role == LanPibApprovalRole.Initiator && request.PeerDeviceId == PeerId &&
                request.PeerFingerprint == Fingerprint(PeerKey), "Initiator approval presented the wrong peer.");
            return Show?.Invoke(request, token) ?? Task.FromResult(true);
        });
        internal ProductPibInitiator Initiator() => new(new(LocalId, "Windows requester", LocalKey),
            SignLocal, Verify, _ => { }, async (_, guard, token) =>
            {
                if (Persist is not null) await Persist(guard, token);
                else { guard(); LocalCommits++; }
            }, Presenter, RequireCurrent, _time);
        internal UsbPeerInspection Target(string id = PeerId)
        {
            var now = _time.GetUtcNow();
            var request = UsbPeerDiscoveryWire.Request(now);
            var unsigned = new UsbPeerDiscoveryResponse(request, new(id, "ML-DSA-65", PeerKey, Fingerprint(PeerKey)),
                "USB peer", "ios", []);
            var response = unsigned with { Signature = SignPeer(UsbPeerDiscoveryWire.SigningData(unsigned)) };
            return UsbPeerInspection.Verify(Udid, response, request, now,
                (identity, data, signature) => Verify(identity.PublicKey, data, signature));
        }
        internal async Task<ReadOnlyMemory<byte>> Exchange(byte[] bytes, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Exchanges++;
            if (LanBootstrapWire.ReadDiscriminator(bytes) == "protocolIdentityBindingRequest")
            {
                Request = LanPibWire.DecodeRequest(bytes);
                var candidate = Responder.CreateCandidate(Request, token);
                return LanPibWire.EncodeCandidate(ChangeCandidate?.Invoke(candidate) ?? candidate);
            }
            Confirm = LanPibWire.DecodeConfirm(bytes);
            var ack = await Responder.ConfirmAsync(Confirm, token);
            return LanPibWire.EncodeFinalAck(ChangeAck?.Invoke(ack) ?? ack);
        }
        internal async Task<ReadOnlyMemory<byte>> SocketExchange(byte[] bytes, CancellationToken token)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var serving = Serve();
            var client = ProductBootstrapExchange.ExchangeAsync(
                current => UsbMuxConnector.ConnectSocket(listener.LocalEndpoint, current),
                bytes, LanBootstrapWire.MaximumBytes, token);
            await Task.WhenAll(client, serving);
            return await client;
            async Task Serve()
            {
                var socket = await listener.AcceptTcpClientAsync(token);
                await using var owner = new ProductControlStreamTransport(socket, LanBootstrapWire.MaximumBytes, LanBootstrapWire.MaximumBytes);
                var request = await owner.ReadAsync(token);
                var response = await Exchange(request.ToArray(), token);
                await owner.SendAsync(response, token);
            }
        }
        public void Dispose() { _localNative?.Dispose(); _peerNative?.Dispose(); }
    }

    private static string Fingerprint(ImmutableArray<byte> key) =>
        new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65, key.ToArray()).AuthoritativeFingerprint;
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static async Task Reject<T>(Func<Task> run) where T : Exception
    {
        try { await run(); } catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name + ".");
    }
    private static async Task RoundTrip()
    {
        using var f = new Fixture(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var initiator = f.Initiator();
        var peer = await initiator.PairUsbAsync(f.Target(), f.SocketExchange, deadline.Token);
        Require(f.Exchanges == 2 && f.LocalCommits == 1 && f.PeerCommits == 1 && f.LocalSas == f.PeerSas &&
            peer.IsProtocolIdentityOnly && peer.ProtocolPublicKey.Span.SequenceEqual(f.PeerKey.AsSpan()), "Pairing did not complete the exact two-sided transaction.");
        Require(f.Request?.BonjourEndpointDigest == Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes($"SkyBridge-USB|{Udid}|9527|{PeerId}"))), "The signed request did not bind the USB route.");
        await Reject<InvalidOperationException>(() => initiator.PairUsbAsync(f.Target(), f.Exchange, default));
    }
    private static async Task ApprovalOrder()
    {
        using var f = new Fixture();
        var shown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var approve = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Show = (_, _) => { shown.SetResult(); return approve.Task; };
        var operation = f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default);
        await shown.Task.WaitAsync(TimeSpan.FromSeconds(3));
        try
        {
            Require(f.Exchanges == 1 && f.PeerApprovals == 0 && f.LocalCommits == 0 && f.PeerCommits == 0,
                "The candidate or local prompt already granted trust.");
        }
        finally { approve.TrySetResult(true); }
        await operation;
        Require(f.LocalCommits == 1 && f.PeerCommits == 1 && f.LocalSas == f.PeerSas, "The approved transcript did not converge.");
    }
    private static async Task Tampering()
    {
        using (var f = new Fixture())
        {
            f.ChangeCandidate = c => c with { DeviceName = "Changed signed name" };
            await Reject<LanPibRejectedException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            Require(f.LocalApprovals == 0 && f.LocalCommits == 0, "Unverified candidate reached approval.");
        }
        using (var f = new Fixture())
        {
            f.ChangeCandidate = c =>
            {
                var changed = c with { DeviceId = "id:bbbbbbbb-cccc-dddd-eeee-ffffffffffff", Aliases = [PeerId] };
                return changed with { Signature = f.SignPeer(LanPibCanonical.CandidatePreimage(changed)) };
            };
            await Reject<InvalidDataException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            Require(f.LocalApprovals == 0, "A valid signature expanded authority to a different selected identity.");
        }
        using (var f = new Fixture())
        {
            f.ChangeAck = ack => ack with { ConfirmationNonce = new byte[32].ToImmutableArray() };
            await Reject<InvalidDataException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            Require(f.PeerCommits == 1 && f.LocalCommits == 0, "Invalid ACK granted local trust or pretended to roll back the remote commit.");
        }
    }
    private static async Task RefusalAndRevocation()
    {
        foreach (bool revoke in new[] { false, true })
        {
            using var f = new Fixture(); f.Show = (_, _) => { f.Current = !revoke; return Task.FromResult(revoke); };
            if (revoke) await Reject<InvalidOperationException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            else await Reject<LanPibRejectedException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            Require(f.Exchanges == 1 && f.LocalCommits == 0 && f.PeerCommits == 0, "Refusal or revocation still confirmed the peer.");
        }
    }
    private static async Task Cancellation()
    {
        using var f = new Fixture(); using var canceled = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Show = (_, _) => { entered.SetResult(); return release.Task; };
        var operation = f.Initiator().PairUsbAsync(f.Target(), f.Exchange, canceled.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); canceled.Cancel();
        try { Require(!operation.IsCompleted, "Cancellation detached the live approval owner."); }
        finally { release.TrySetResult(true); }
        await Reject<OperationCanceledException>(() => operation);
        Require(f.Exchanges == 1 && f.LocalCommits == 0, "Canceled approval was published.");
    }
    private static async Task LateApproval()
    {
        using var f = new Fixture(); f.Show = (_, _) => { f.Clock.Advance(180); return Task.FromResult(true); };
        await f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default);
        Require(f.LocalCommits == 1 && f.PeerCommits == 1, "Valid three-minute human comparison was rejected.");
    }
    private static async Task ClockLimits()
    {
        foreach (int mode in new[] { 0, 1, 2 })
        {
            using var f = new Fixture();
            f.Show = (_, _) =>
            {
                if (mode == 0) f.Clock.Now -= TimeSpan.FromMilliseconds(1);
                else f.Clock.Advance(301, wall: mode == 1);
                return Task.FromResult(true);
            };
            await Reject<InvalidOperationException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            Require(f.Exchanges == 1 && f.LocalCommits == 0, "The clock change revived pairing authority.");
        }
    }
    private static async Task CommitBoundary()
    {
        using (var f = new Fixture())
        {
            var failure = new IOException("Injected durable-store failure.");
            f.Persist = (_, _) => Task.FromException(failure);
            try { await f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default); throw new InvalidOperationException("Missing persistence failure."); }
            catch (IOException error) { Require(ReferenceEquals(error, failure), "Persistence failure context changed."); }
            Require(f.LocalCommits == 0 && f.PeerCommits == 1, "Failure was represented as local success or remote rollback.");
        }
        using (var f = new Fixture())
        {
            f.Persist = (guard, _) => { f.Clock.Advance(301); guard(); f.LocalCommits++; return Task.CompletedTask; };
            await Reject<InvalidOperationException>(() => f.Initiator().PairUsbAsync(f.Target(), f.Exchange, default));
            Require(f.LocalCommits == 0, "Expired authority crossed the durable-commit guard.");
        }
        using (var f = new Fixture())
        using (var canceled = new CancellationTokenSource())
        {
            f.Persist = (guard, _) => { guard(); f.LocalCommits++; canceled.Cancel(); return Task.CompletedTask; };
            await f.Initiator().PairUsbAsync(f.Target(), f.Exchange, canceled.Token);
            Require(f.LocalCommits == 1, "Cancellation after durable commit became an alleged rollback.");
        }
    }
    private static async Task DiscoveryAdmission()
    {
        using (var f = new Fixture())
        {
            var target = f.Target(); f.Clock.Advance(31);
            await Reject<InvalidDataException>(() => f.Initiator().PairUsbAsync(target, f.Exchange, default));
            Require(f.Exchanges == 0, "Stale discovery initiated enrollment.");
        }
        using (var f = new Fixture())
        {
            await Reject<LanPibRejectedException>(() => f.Initiator().PairUsbAsync(f.Target(LocalId[3..]), f.Exchange, default));
            Require(f.Exchanges == 0, "The local stable ID was accepted with another key.");
        }
    }
    private static async Task RemoteFailure()
    {
        using var f = new Fixture();
        await Reject<LanPibRejectedException>(() => f.Initiator().PairUsbAsync(f.Target(), (bytes, _) =>
        {
            var request = LanPibWire.DecodeRequest(bytes);
            ReadOnlyMemory<byte> wire = LanBootstrapWire.Encode("kemRefreshFailure", new
            {
                version = 1, requesterDeviceId = request.RequesterDeviceId, targetDeviceId = request.TargetDeviceId,
                stage = "identity_binding", reasonCode = "userRejected", reason = "Rejected",
                sentAt = request.SentAt, requestHashHex = LanPibCanonical.RequestHash(request)
            });
            return Task.FromResult(wire);
        }, default));
        Require(f.LocalApprovals == 0 && f.LocalCommits == 0, "Unsigned diagnostic became approval or trust.");
    }
    private static async Task NativePersistence()
    {
        using var f = new Fixture(native: true);
        var directory = Directory.CreateTempSubdirectory("skybridge-usb-pib-native-");
        try
        {
            using (var identity = await RemoteControlIdentityStore.LoadOrCreateAsync(directory.FullName, "USB requester"))
            {
                Require(identity.TrustedMaterials.Count == 0, "Native requester state was not fresh.");
                var initiator = identity.CreatePibInitiator(f.Presenter, f.RequireCurrent);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                await initiator.PairUsbAsync(f.Target(), f.SocketExchange, deadline.Token);
                Require(identity.TrustedMaterials.Count == 1 && identity.TrustedMaterials[0].IsProtocolIdentityOnly,
                    "Enrollment did not preserve the identity-only trust boundary.");
            }
            using var restored = await RemoteControlIdentityStore.LoadExistingAsync(directory.FullName, "USB requester");
            Require(restored.TrustedMaterials.Single().ProtocolPublicKey.Span.SequenceEqual(f.PeerKey.AsSpan()) &&
                f.PeerApprovals == 1 && f.LocalApprovals == 1 && f.LocalSas == f.PeerSas,
                "Native verified trust did not survive DPAPI reload.");
        }
        finally { Directory.Delete(directory.FullName, recursive: true); }
    }
}
