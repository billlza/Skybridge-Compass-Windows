using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

internal static class SignedLanKemRefreshInitiatorTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("SKR initiator binds fresh USB nonce exact saved signer and one-use route lease", RoundTrip),
        ("SKR initiator negotiates only the signed complete supported PQC intersection", Negotiation),
        ("SKR initiator rejects signed changes to request route nonce suite and signer", Tampering),
        ("SKR initiator rejects an alias-only target and never expands saved trust", Aliases),
        ("SKR initiator checks saved authority before exchange after verification and key use", Authority),
        ("SKR initiator bounds response and verification duration without reviving stale discovery", AdmissionTime),
        ("SKR key lease expires on wall or elapsed time and rejects clock rollback", LeaseTime),
        ("SKR initiator waits for actual noncooperative exchange before cancellation completes", Cancellation),
        ("SKR initiator response deadline cancels the owned exchange", Deadline),
        ("SKR initiator treats unsigned remote diagnostics solely as failures", RemoteFailure)
    ];
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
        internal long Stamp;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Stamp;
        internal void Advance(double seconds, bool wall = true)
        { Stamp += TimeSpan.FromSeconds(seconds).Ticks; if (wall) Now += TimeSpan.FromSeconds(seconds); }
    }
    private sealed class Fixture
    {
        internal readonly Clock Clock = new();
        internal readonly LanKemRefreshInventory Local, Remote;
        internal readonly UsbPeerInspection Selected;
        internal readonly RemoteControlPairingMaterial Original;
        internal RemoteControlPairingMaterial Paired;
        internal bool Current = true;
        internal int Exchanges, Verifications;
        internal Action? AfterVerify;
        internal Func<LanSignedKemRefresh, LanSignedKemRefresh>? Change;
        internal LanKemRefreshRequest? Request;
        internal bool Resign = true;
        internal Fixture()
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "skr3-golden.json")));
            var vector = doc.RootElement.GetProperty("vectors")[0];
            var response = SignedLanKemRefreshWire.DecodeResponse(Encoding.UTF8.GetBytes(
                "{\"signedKEMRefresh\":" + vector.GetProperty("response").GetRawText() + "}"));
            var localKey = Enumerable.Repeat((byte)19, 1952).ToImmutableArray();
            Local = new("id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", localKey,
                response.KemPublicKeys.Where(k => k.SuiteWireId != 1).ToImmutableArray(),
                "windows", "Windows 10.0.26100", response.QPeriaptAuthProfile!);
            Remote = Local with { DeviceId = "id:11111111-2222-3333-4444-555555555555", SigningPublicKey = response.ProtocolIdentityPublicKey };
            Original = Paired = RemoteControlPairingMaterial.CreateProtocolIdentity(Remote.DeviceId, "USB peer", Remote.SigningPublicKey.AsSpan());
            var request = UsbPeerDiscoveryWire.Request(Clock.Now);
            var unsigned = new UsbPeerDiscoveryResponse(request,
                new(Remote.DeviceId[3..], "ML-DSA-65", Remote.SigningPublicKey, Original.ProtocolPublicKeyFingerprint), "USB peer", "ios", [1]);
            var signed = unsigned with { Signature = Sign(Remote.SigningPublicKey, UsbPeerDiscoveryWire.SigningData(unsigned)) };
            Selected = UsbPeerInspection.Verify("00008132-1111111111111111", signed, request, Clock.Now,
                (identity, bytes, signature) => VerifyControlled(identity.PublicKey, bytes, signature));
        }
        internal void RequireCurrent() { if (!Current) throw new InvalidOperationException("Controlled account revoked."); }
        internal SignedLanKemRefreshInitiator New(TimeSpan? timeout = null) => new(Local, () => Paired, (key, bytes, signature) =>
        { VerifyControlled(key, bytes, signature); Verifications++; AfterVerify?.Invoke(); }, RequireCurrent, Clock, timeout);
        internal Task<ReadOnlyMemory<byte>> Exchange(byte[] wire, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Exchanges++;
            Request = SignedLanKemRefreshWire.DecodeRequest(wire);
            var responder = new SignedLanKemRefreshResponder(Remote,
                [new(Local.DeviceId, Request.RequesterProtocolIdentityFingerprint!)],
                bytes => Sign(Remote.SigningPublicKey, bytes), RequireCurrent, Clock);
            var response = responder.Respond(Request, token);
            if (Change is { } change)
            {
                response = change(response);
                if (Resign) response = response with { Signature = Sign(Remote.SigningPublicKey, SignedLanKemRefreshCanonical.ResponsePreimage(response)) };
            }
            return Task.FromResult<ReadOnlyMemory<byte>>(LanBootstrapWire.Encode("signedKEMRefresh", response));
        }
        internal Task<SignedKemRefreshLease> Refresh(CancellationToken token = default) => New().RefreshUsbAsync(Selected, Exchange, token);
        // These host ports exercise message/state binding, not cryptographic assurance.
        // Native Windows workspace coverage separately verifies ML-DSA signatures.
        private static ImmutableArray<byte> Sign(ImmutableArray<byte> key, byte[] bytes) =>
            SHA256.HashData(key.Concat(bytes).ToArray()).ToImmutableArray();
        private static void VerifyControlled(ImmutableArray<byte> key, byte[] bytes, ImmutableArray<byte> signature)
        { if (!Sign(key, bytes).AsSpan().SequenceEqual(signature.AsSpan())) throw new CryptographicException("Controlled signature mismatch."); }
    }
    private static async Task RoundTrip()
    {
        var f = new Fixture(); var initiator = f.New();
        var lease = await initiator.RefreshUsbAsync(f.Selected, f.Exchange, default);
        Require(f.Request is { Version: 3, PolicyRequirePQC: true, PolicyAllowClassicFallback: false, RouteScope: "lan" } &&
            f.Request.BonjourEndpointDigest == f.Selected.EndpointDigest && f.Request.Nonce.Length == 32 &&
            f.Verifications == 1 && ReferenceEquals(f.Paired, f.Original), "Refresh changed authority or omitted verified route/policy binding.");
        await Reject<InvalidDataException>(() => Task.FromResult(lease.ClaimKeys(lease.PeerDeviceId, lease.Fingerprint, new string('0',64))));
        var keys = lease.ClaimKeys(lease.PeerDeviceId, lease.Fingerprint, lease.EndpointDigest);
        Require(keys.Select(k => k.SuiteWireId).SequenceEqual(new[] { 18, 257 }), "Complete signed KEM intersection changed.");
        await Reject<InvalidOperationException>(() => Task.FromResult(lease.ClaimKeys(lease.PeerDeviceId, lease.Fingerprint, lease.EndpointDigest)));
        await Reject<InvalidOperationException>(() => initiator.RefreshUsbAsync(f.Selected, f.Exchange, default));
        Require(f.Exchanges == 1, "Single-use refresh caused an automatic retry.");
    }
    private static async Task Negotiation()
    {
        var f = new Fixture();
        f.Change = r => r with { KemPublicKeys = r.KemPublicKeys.Where(k => k.SuiteWireId == 257).ToImmutableArray(),
            PermittedSuiteWireIds = [257], QPeriaptAuthProfile = null };
        var lease = await f.Refresh();
        Require(lease.ClaimKeys(lease.PeerDeviceId, lease.Fingerprint, lease.EndpointDigest).Single().SuiteWireId == 257,
            "Unsupported Q was used instead of the signed common PQC suite.");
        f = new(); f.Change = r => r with { KemPublicKeys = [], PermittedSuiteWireIds = [], QPeriaptAuthProfile = null };
        await Reject<LanKemRefreshRejectedException>(() => f.Refresh());
        Require(f.Verifications == 1, "An empty signed intersection was classified before signature verification.");
    }
    private static async Task Tampering()
    {
        Func<LanSignedKemRefresh, LanSignedKemRefresh>[] changes =
        [
            r => r with { RequestNonce = Enumerable.Repeat((byte)0,32).ToImmutableArray() },
            r => r with { RequestHashHex = new string('f',64) },
            r => r with { BonjourEndpointDigest = new string('e',64) },
            r => r with { KemPublicKeys = r.KemPublicKeys.Where(k => k.SuiteWireId == 257).ToImmutableArray() },
            r => r with { PolicyRequirePQC = false },
            r => r with { ExpiresAt = r.SentAt - 1 },
            r => r with { ProtocolIdentityPublicKey = Enumerable.Repeat((byte)18,1952).ToImmutableArray() },
            r => r with { Generation = -1 }
        ];
        foreach (var change in changes)
        {
            var f = new Fixture { Change = change, Resign = false };
            await Reject<InvalidDataException>(() => f.Refresh());
            Require(f.Exchanges == 1 && ReferenceEquals(f.Paired,f.Original), "Invalid reply caused retry or trust modification.");
        }
        var signature = new Fixture { Change = r => r with { Signature = [0] }, Resign = false };
        await Reject<CryptographicException>(() => signature.Refresh());
    }
    private static async Task Aliases()
    {
        var f = new Fixture { Change = r => r with { DeviceId = "id:unapproved-alias", Aliases = [r.DeviceId] } };
        await Reject<InvalidDataException>(() => f.Refresh());
        f = new Fixture { Change = r => r with { Aliases = ["id:unapproved-alias"],
            ProtocolIdentityFingerprint = r.ProtocolIdentityFingerprint.ToUpperInvariant() } };
        var lease = await f.Refresh();
        Require(lease.PeerDeviceId == f.Paired.DeviceId && lease.Fingerprint == f.Original.ProtocolPublicKeyFingerprint &&
            ReferenceEquals(f.Paired, f.Original), "Canonical identity changed or signed aliases enlarged saved authority.");
        await Reject<InvalidDataException>(() => Task.FromResult(lease.ClaimKeys("id:unapproved-alias", lease.Fingerprint, lease.EndpointDigest)));
    }
    private static async Task Authority()
    {
        var f = new Fixture(); f.Paired = RemoteControlPairingMaterial.CreateProtocolIdentity(f.Original.DeviceId, "replacement", f.Local.SigningPublicKey.AsSpan());
        await Reject<InvalidDataException>(() => f.Refresh()); Require(f.Exchanges == 0, "Unpaired signer reached exchange.");
        f = new(); f.AfterVerify = () => f.Current = false;
        await Reject<InvalidOperationException>(() => f.Refresh());
        f = new(); var lease = await f.Refresh(); f.Current = false;
        await Reject<InvalidOperationException>(() => Task.Run(lease.RequireCurrent));
        f = new(); lease = await f.Refresh();
        f.Paired = RemoteControlPairingMaterial.CreateProtocolIdentity(f.Original.DeviceId, "replacement", f.Local.SigningPublicKey.AsSpan());
        await Reject<InvalidDataException>(() => Task.Run(lease.RequireCurrent));
        f = new(); using var canceled = new CancellationTokenSource(); lease = await f.Refresh(canceled.Token);
        canceled.Cancel(); await Reject<OperationCanceledException>(() => Task.Run(lease.RequireCurrent));
    }
    private static async Task AdmissionTime()
    {
        var f = new Fixture(); f.Clock.Advance(31);
        await Reject<InvalidDataException>(() => f.Refresh()); Require(f.Exchanges == 0, "Expired discovery reached refresh.");
        f = new(); f.Change = r => { f.Clock.Advance(21); return r; };
        await Reject<TimeoutException>(() => f.Refresh());
        f = new(); f.AfterVerify = () => f.Clock.Advance(21);
        await Reject<TimeoutException>(() => f.Refresh());
    }
    private static async Task LeaseTime()
    {
        foreach (int mode in new[] { 0, 1, 2, 3, 4 })
        {
            var f = new Fixture(); var lease = await f.Refresh();
            if (mode == 0) f.Clock.Now += TimeSpan.FromMinutes(5);
            if (mode == 1) f.Clock.Advance(300, wall: false);
            if (mode == 2) f.Clock.Now -= TimeSpan.FromMilliseconds(1);
            if (mode == 3) f.Clock.Stamp--;
            if (mode == 4) { f.Clock.Advance(2); lease.RequireCurrent(); f.Clock.Stamp--; }
            await Reject<InvalidOperationException>(() => Task.Run(lease.RequireCurrent));
        }
        var shortLease = new Fixture { Change = r => r with { ExpiresAt = r.SentAt + 1 } };
        var current = await shortLease.Refresh(); shortLease.Clock.Advance(1);
        await Reject<InvalidOperationException>(() => Task.Run(current.RequireCurrent));
    }
    private static async Task Cancellation()
    {
        var f = new Fixture(); using var canceled = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = f.New().RefreshUsbAsync(f.Selected, async (bytes, _) =>
        { entered.TrySetResult(); await release.Task; return await f.Exchange(bytes, default); }, canceled.Token);
        await entered.Task; canceled.Cancel();
        try { Require(!pending.IsCompleted, "Cancellation detached the actual exchange owner."); }
        finally { release.TrySetResult(); }
        await Reject<OperationCanceledException>(() => pending);
        Require(f.Verifications == 0, "Canceled reply reached verification or key publication.");
    }
    private static async Task Deadline()
    {
        var f = new Fixture(); bool drained = false;
        await Reject<TimeoutException>(() => f.New(TimeSpan.FromMilliseconds(50)).RefreshUsbAsync(f.Selected, async (_, token) =>
        { try { await Task.Delay(Timeout.InfiniteTimeSpan, token); throw new InvalidOperationException(); } finally { drained = true; } }, default));
        Require(drained, "Response deadline returned before the exchange unwound.");
    }
    private static async Task RemoteFailure()
    {
        foreach (bool bound in new[] { true, false })
        {
            var f = new Fixture(); int calls = 0;
            async Task Run() => _ = await f.New().RefreshUsbAsync(f.Selected, (bytes, _) =>
            {
                calls++; var request = SignedLanKemRefreshWire.DecodeRequest(bytes);
                if (!bound) request = request with { Nonce = Enumerable.Repeat((byte)1,32).ToImmutableArray() };
                return Task.FromResult<ReadOnlyMemory<byte>>(LanBootstrapWire.Encode("kemRefreshFailure", new
                {
                    version = 1, requesterDeviceId = request.RequesterDeviceId, targetDeviceId = request.TargetDeviceId,
                    stage = "kem_refresh", reasonCode = "untrustedRequester", reason = "Rejected", sentAt = request.SentAt,
                    requestHashHex = SignedLanKemRefreshCanonical.RequestHash(request)
                }));
            }, default);
            if (bound) await Reject<LanKemRefreshRejectedException>(Run); else await Reject<InvalidDataException>(Run);
            Require(calls == 1 && f.Verifications == 0, "Unsigned diagnostic caused retry or key publication.");
        }
    }
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static async Task Reject<T>(Func<Task> call) where T : Exception
    { try { await call(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
