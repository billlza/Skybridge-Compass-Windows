using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

internal static class LanPibResponderTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("PIB candidate verifies possession without approval or trust commit", CandidateOnly),
        ("PIB final ACK waits for actual approval and persistence completion", ApprovalAndCommitOrder),
        ("PIB invalid request and confirmation signatures never reach approval", BadSignatures),
        ("PIB declined confirmation remains failed without a successful ACK", Declined),
        ("PIB cancellation retains a noncooperative approval owner until actual completion", CancellationOwnership),
        ("PIB account revocation after approval prevents signing and persistence", Revocation),
        ("PIB persistence failure never becomes a cached successful ACK", CommitFailure),
        ("PIB expiry at persistence effect admission prevents the commit", CommitDeadline),
        ("PIB native signing delay cannot outlive the approved parent deadline", SigningDeadline),
        ("PIB three-minute SAS comparison stays valid within the original transaction", LateConfirmation),
        ("PIB approval cancellation follows the earlier remaining parent deadline", ApprovalDeadline),
        ("PIB lost ACK retry preserves exact signed bytes and does not recommit", ExactRetry),
        ("PIB concurrent exact confirmations share one real approval and commit", ConcurrentConfirmations),
        ("PIB canceled duplicate waits for owner without canceling primary approval", CanceledDuplicate),
        ("PIB candidate retry preserves SAS and rejects changed request signatures", CandidateRetry),
        ("PIB monotonic expiry cannot resurrect a request while wall time stalls", ElapsedExpiry),
        ("PIB rollback and expired candidates fail closed", ClockBounds),
        ("PIB quotas normalize fingerprint case and do not evict live transactions", Capacity),
        ("PIB admission rate includes identical retries and has a bounded window", RateLimit),
        ("PIB global attempt limit bounds rejected identities after transaction capacity fills", GlobalRateLimit),
        ("PIB rejects unsupported algorithms wrong targets and self pairing before crypto", Unsupported),
        ("PIB actual two-socket bootstrap works before any trusted peer exists", TwoConnections),
        ("PIB TCP rejection is diagnostic only and never enters MAIN", SocketRejection),
        ("PIB commit becomes visible to a later signed KEM refresh without restarting", FreshRefreshAuthority)
    ];
    private const string LocalId = "id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string PeerId = "id:11111111-2222-3333-4444-555555555555";
    private static ImmutableArray<byte> Bytes(byte b, int count) => Enumerable.Repeat(b, count).ToImmutableArray();
    private static string Fingerprint(ImmutableArray<byte> key) =>
        new WebRtcProductProtocolIdentityPublicKey(WebRtcProductSignatureAlgorithm.MlDsa65, key.ToArray()).AuthoritativeFingerprint;
    private static void Require(bool condition, string reason) { if (!condition) throw new InvalidOperationException(reason); }
    private static async Task Reject(Func<Task> action, string? code = null)
    {
        try { await action(); }
        catch (LanPibRejectedException error) when (code is null || error.Code == code) { return; }
        catch (Exception error) when (code is null && error is OperationCanceledException or InvalidOperationException or InvalidDataException) { return; }
        throw new InvalidOperationException("Expected pairing rejection was not observed: " + code);
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
        private long _stamp;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _stamp;
        internal void Advance(double seconds, bool wall = true)
        { _stamp += TimeSpan.FromSeconds(seconds).Ticks; if (wall) Now += TimeSpan.FromSeconds(seconds); }
        internal double Reference => Now.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0;
    }
    private sealed class Approval(Func<LanPibApprovalRequest, CancellationToken, Task<bool>> show) : ILanPibApprovalPresenter
    {
        public Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token) => show(request, token);
    }
    private sealed class Fixture
    {
        internal Clock Clock = new();
        internal ImmutableArray<byte> LocalKey = Bytes(12, 1952);
        internal LanPibRequest Request;
        internal LanPibResponder Responder;
        internal bool Current = true;
        internal int Signs, Verifies, Approvals, Commits;
        internal RemoteControlTrustedPeer[] Trusted = [];
        internal Func<LanPibApprovalRequest, CancellationToken, Task<bool>>? Show;
        internal Func<Action, CancellationToken, Task>? Persist;
        internal Action<int>? OnSign;
        internal Fixture()
        {
            Request = NewRequest(0);
            // Deliberately controlled SHA-256 ports isolate the actual transaction,
            // wire, timing, ownership and persistence boundaries. They are not PQC.
            Responder = new(new(LocalId, "Windows fixture", LocalKey), bytes =>
            {
                Signs++; OnSign?.Invoke(Signs); return SHA256.HashData(bytes).ToImmutableArray();
            }, (key, bytes, signature) =>
            {
                Verifies++;
                Require(key.Length == 1952, "Verification did not receive a frozen ML-DSA-65 key.");
                if (!signature.AsSpan().SequenceEqual(SHA256.HashData(bytes)))
                    throw new LanPibRejectedException("signatureInvalid", "Controlled fixture signature differs.");
            }, _ => { }, async (material, guard, token) =>
            {
                if (Persist is not null) await Persist(guard, token);
                guard();
                Trusted = [new(material.DeviceId, material.ProtocolPublicKeyFingerprint)];
                Commits++;
            }, new Approval((request, token) =>
            {
                Approvals++; request.RequireCurrent();
                Require(request.SasCode.Length == 6, "Approval did not contain a six-digit transcript SAS.");
                return Show?.Invoke(request, token) ?? Task.FromResult(true);
            }), () => { if (!Current) throw new InvalidOperationException("fixture account revoked"); }, Clock);
        }
        internal LanPibRequest NewRequest(byte identity, bool upperFingerprint = false)
        {
            var key = Bytes((byte)(30 + identity), 1952);
            var request = new LanPibRequest(3, Guid.NewGuid().ToString("D"),
                identity == 0 ? PeerId : $"id:requester-{identity:D3}", LocalId, ["ML-DSA-65", "Ed25519"], "ML-DSA-65", key,
                upperFingerprint ? Fingerprint(key).ToUpperInvariant() : Fingerprint(key), [], Bytes(identity, 24), Clock.Reference);
            return Sign(request);
        }
        internal static LanPibRequest Sign(LanPibRequest request) => request with
        { RequesterSignature = SHA256.HashData(LanPibCanonical.RequestPreimage(request)).ToImmutableArray() };
        internal static LanPibConfirm Sign(LanPibConfirm confirm) => confirm with
        { RequesterSignature = SHA256.HashData(LanPibCanonical.ConfirmPreimage(confirm)).ToImmutableArray() };
        internal LanPibCandidate Candidate() => Responder.CreateCandidate(Request, default);
        internal LanPibConfirm Confirm(LanPibCandidate candidate) => MakeConfirm(Request, candidate, Clock.Reference);
        internal static LanPibConfirm MakeConfirm(LanPibRequest request, LanPibCandidate candidate, double now) => Sign(new LanPibConfirm(
            3, request.TransactionId, request.RequesterDeviceId, candidate.DeviceId,
            request.RequesterProtocolIdentityFingerprint, candidate.ProtocolIdentityFingerprint, request.Nonce,
            LanPibCanonical.RequestHash(request), LanPibCanonical.CandidateHash(candidate), LanPibCanonical.SasTranscriptHash(request, candidate),
            Bytes(63, 24), now, candidate.ExpiresAt, []));
        internal SignedLanKemRefreshResponder Refresh()
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "skr3-golden.json")));
            var response = SignedLanKemRefreshWire.DecodeResponse(Encoding.UTF8.GetBytes("{\"signedKEMRefresh\":" +
                doc.RootElement.GetProperty("vectors")[0].GetProperty("response").GetRawText() + "}"));
            return new(new(LocalId, LocalKey, response.KemPublicKeys.Where(k => k.SuiteWireId != 1).ToImmutableArray(),
                "windows", "Windows 10.0.26100", response.QPeriaptAuthProfile!), () => Trusted,
                bytes => SHA256.HashData(bytes).ToImmutableArray(),
                () => { if (!Current) throw new InvalidOperationException("fixture account revoked"); }, Clock);
        }
    }
    private static Task CandidateOnly()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        Require(f.Verifies == 1 && f.Signs == 1, $"Candidate crypto calls differ: verifies={f.Verifies}, signs={f.Signs}.");
        Require(f.Approvals == 0 && f.Commits == 0 && f.Trusted.Length == 0, "Candidate granted authority.");
        LanPibValidation.RequireCandidateBindings(f.Request, candidate, Fingerprint(f.LocalKey), f.Clock.Now.ToUnixTimeMilliseconds());
        return Task.CompletedTask;
    }
    private static async Task ApprovalAndCommitOrder()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        var shown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var approval = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var committing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var commit = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Show = (_, _) => { shown.SetResult(); return approval.Task; };
        f.Persist = async (guard, _) => { guard(); committing.SetResult(); await commit.Task; };
        var confirm = f.Confirm(candidate); var pending = f.Responder.ConfirmAsync(confirm, default);
        await shown.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Require(!pending.IsCompleted && f.Signs == 1 && f.Commits == 0, "ACK or commit preceded approval.");
        approval.SetResult(true); await committing.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Require(!pending.IsCompleted && f.Commits == 0, "ACK preceded actual persistence completion.");
        commit.SetResult(); var ack = await pending;
        f.Responder.RequireAckSend(confirm, ack, default);
        Require(f.Commits == 1 && f.Signs == 2, "The approved transaction did not commit exactly once.");
    }
    private static async Task BadSignatures()
    {
        var f = new Fixture();
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(f.Request with { RequesterSignature = Bytes(1, 32) }, default)), "signatureInvalid");
        Require(f.Signs == 0 && f.Approvals == 0 && f.Commits == 0, "Invalid request reached authority work.");
        var candidate = f.Candidate(); var confirm = f.Confirm(candidate);
        await Reject(() => f.Responder.ConfirmAsync(confirm with { RequesterSignature = Bytes(2, 32) }, default), "signatureInvalid");
        Require(f.Approvals == 0 && f.Commits == 0, "Invalid confirmation reached approval.");
        _ = await f.Responder.ConfirmAsync(confirm, default);
    }
    private static async Task Declined()
    {
        var f = new Fixture(); var candidate = f.Candidate(); f.Show = (_, _) => Task.FromResult(false);
        var confirm = f.Confirm(candidate);
        await Reject(() => f.Responder.ConfirmAsync(confirm, default), "userRejected");
        await Reject(() => f.Responder.ConfirmAsync(confirm, default), "replay");
        Require(f.Approvals == 1 && f.Signs == 1 && f.Commits == 0, "Decline became trust or repeated approval.");
    }
    private static async Task CancellationOwnership()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        var shown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Show = (_, _) => { shown.SetResult(); return release.Task; };
        using var scope = new CancellationTokenSource();
        var pending = f.Responder.ConfirmAsync(f.Confirm(candidate), scope.Token);
        await shown.Task.WaitAsync(TimeSpan.FromSeconds(5)); scope.Cancel();
        Require(!pending.IsCompleted, "Cancellation detached the real approval owner.");
        release.SetResult(true); await Reject(async () => await pending);
        Require(f.Signs == 1 && f.Commits == 0, "Canceled approval committed trust.");
    }
    private static async Task Revocation()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        f.Show = (_, _) => { f.Current = false; return Task.FromResult(true); };
        await Reject(() => f.Responder.ConfirmAsync(f.Confirm(candidate), default));
        Require(f.Signs == 1 && f.Commits == 0, "Revoked account signed an ACK or persisted.");
    }
    private static async Task CommitFailure()
    {
        var f = new Fixture(); var candidate = f.Candidate(); var confirm = f.Confirm(candidate);
        f.Persist = (_, _) => throw new IOException("fixture disk failure");
        try { await f.Responder.ConfirmAsync(confirm, default); throw new InvalidOperationException("Commit failure became success."); }
        catch (IOException error) when (error.Message == "fixture disk failure") { }
        await Reject(() => f.Responder.ConfirmAsync(confirm, default), "replay");
        Require(f.Commits == 0, "Failed persistence published authority.");
    }
    private static async Task CommitDeadline()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        f.Persist = (guard, _) => { f.Clock.Advance(301); guard(); return Task.CompletedTask; };
        await Reject(() => f.Responder.ConfirmAsync(f.Confirm(candidate), default), "expired");
        Require(f.Commits == 0, "Expired final effect admission committed authority.");
    }
    private static async Task SigningDeadline()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        f.OnSign = n => { if (n == 2) f.Clock.Advance(301); };
        await Reject(() => f.Responder.ConfirmAsync(f.Confirm(candidate), default), "expired");
        Require(f.Commits == 0, "Slow signer committed an expired pairing.");
    }
    private static async Task LateConfirmation()
    {
        var f = new Fixture(); var candidate = f.Candidate(); f.Clock.Advance(180);
        var ack = await f.Responder.ConfirmAsync(f.Confirm(candidate), default);
        Require(f.Commits == 1 && ack.ExpiresAt == candidate.ExpiresAt, "Legitimate SAS comparison was rejected or renewed.");
    }
    private static async Task ExactRetry()
    {
        var f = new Fixture(); var candidate = f.Candidate(); var confirm = f.Confirm(candidate);
        var first = await f.Responder.ConfirmAsync(confirm, default); f.Clock.Advance(2);
        var second = await f.Responder.ConfirmAsync(LanPibWire.DecodeConfirm(LanPibWire.EncodeConfirm(confirm)), default);
        Require(ReferenceEquals(first, second) && LanPibWire.EncodeFinalAck(first).SequenceEqual(LanPibWire.EncodeFinalAck(second)) &&
            f.Approvals == 1 && f.Commits == 1 && f.Signs == 2, "ACK recovery renewed or recommitted the transaction.");
        var changed = Fixture.Sign(confirm with { ConfirmationNonce = Bytes(64, 24) });
        await Reject(() => f.Responder.ConfirmAsync(changed, default), "conflictingConfirmation");
    }
    private static async Task ApprovalDeadline()
    {
        var f = new Fixture(); var candidate = f.Candidate(); f.Clock.Advance(299.8);
        f.Show = async (_, token) => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return true; };
        using var owner = new CancellationTokenSource();
        var pending = f.Responder.ConfirmAsync(f.Confirm(candidate), owner.Token);
        try
        {
            await Reject(async () => await pending.WaitAsync(TimeSpan.FromSeconds(2)));
            Require(!owner.IsCancellationRequested && f.Commits == 0 && f.Signs == 1,
                "Parent deadline required caller cancellation or allowed a commit.");
        }
        finally
        {
            owner.Cancel();
            try { await pending; }
            catch (OperationCanceledException) { }
            catch (LanPibRejectedException error) when (error.Code == "expired") { }
        }
    }
    private static Task ConcurrentConfirmations() => Duplicate(false);
    private static Task CanceledDuplicate() => Duplicate(true);
    private static async Task Duplicate(bool cancelDuplicate)
    {
        var f = new Fixture(); var candidate = f.Candidate(); var confirm = f.Confirm(candidate);
        var shown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Show = (_, _) => { shown.SetResult(); return release.Task; };
        var first = f.Responder.ConfirmAsync(confirm, default); await shown.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var duplicateScope = new CancellationTokenSource();
        var second = f.Responder.ConfirmAsync(confirm, duplicateScope.Token);
        if (cancelDuplicate) duplicateScope.Cancel();
        Require(!first.IsCompleted && !second.IsCompleted && f.Approvals == 1 && f.Verifies == 2, "Duplicate created another owner.");
        release.SetResult(true); var ack = await first;
        if (cancelDuplicate) await Reject(async () => await second);
        else Require(ReferenceEquals(ack, await second), "Concurrent exact retry did not share its ACK.");
        Require(f.Commits == 1 && f.Signs == 2, "Concurrent confirmation committed twice.");
    }
    private static async Task CandidateRetry()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        Require(ReferenceEquals(candidate, f.Candidate()) && f.Signs == 1 && f.Verifies == 1, "Candidate retry changed signed state.");
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(f.Request with { RequesterSignature = Bytes(1, 32) }, default)), "conflictingTransaction");
    }
    private static async Task ElapsedExpiry()
    {
        var f = new Fixture(); var candidate = f.Candidate(); f.Clock.Advance(301, wall: false);
        await Reject(() => Task.FromResult(f.Candidate()), "expired");
        await Reject(() => f.Responder.ConfirmAsync(f.Confirm(candidate), default), "expired");
        Require(f.Signs == 1 && f.Commits == 0, "Elapsed transaction was resurrected by a stalled wall clock.");
    }
    private static async Task ClockBounds()
    {
        var f = new Fixture(); var candidate = f.Candidate(); f.Clock.Now -= TimeSpan.FromMilliseconds(1);
        await Reject(() => Task.FromResult(f.Candidate()), "clockRollback");
        f = new(); candidate = f.Candidate(); var confirm = f.Confirm(candidate); f.Clock.Advance(301);
        await Reject(() => f.Responder.ConfirmAsync(confirm, default), "transactionMissingOrExpired");
    }
    private static async Task Capacity()
    {
        var f = new Fixture();
        for (int i = 0; i < 4; i++) _ = f.Responder.CreateCandidate(f.NewRequest(0, upperFingerprint: i % 2 != 0), default);
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(f.NewRequest(0), default)), "capacityReached");
        f = new();
        for (byte identity = 0; identity < 8; identity++)
            for (int i = 0; i < 4; i++) _ = f.Responder.CreateCandidate(f.NewRequest(identity), default);
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(f.NewRequest(8), default)), "capacityReached");
        Require(f.Signs == 32, "Capacity pressure evicted an unexpired transaction.");
    }
    private static async Task RateLimit()
    {
        var f = new Fixture(); var candidate = f.Candidate();
        for (int i = 1; i < 8; i++) _ = f.Candidate();
        await Reject(() => Task.FromResult(f.Candidate()), "rateLimited");
        f.Clock.Advance(10); Require(ReferenceEquals(candidate, f.Candidate()), "Expired rate window changed the transaction.");
    }
    private static async Task Unsupported()
    {
        var f = new Fixture();
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(Fixture.Sign(f.Request with { RequestedProtocolSigningAlgorithms = ["Ed25519"] }), default)), "unsupportedSignatureAlgorithm");
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(Fixture.Sign(f.Request with { TargetDeviceId = "id:wrong-device" }), default)), "targetIdentityMismatch");
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(Fixture.Sign(f.Request with { RequesterDeviceId = LocalId }), default)), "selfPairing");
        Require(f.Signs == 0 && f.Verifies == 0 && f.Approvals == 0, "Unsupported request reached crypto or approval.");
    }
    private static async Task GlobalRateLimit()
    {
        var f = new Fixture();
        for (byte identity = 1; identity <= 32; identity++)
            _ = f.Responder.CreateCandidate(f.NewRequest(identity), default);
        for (byte identity = 33; identity <= 64; identity++)
        {
            var request = f.NewRequest(identity);
            await Reject(() => Task.FromResult(f.Responder.CreateCandidate(request, default)), "capacityReached");
        }
        await Reject(() => Task.FromResult(f.Responder.CreateCandidate(f.NewRequest(65), default)), "rateLimited");
        Require(f.Verifies == 32 && f.Signs == 32, "Overflow identities reached crypto after capacity filled.");
    }
    private static async Task<byte[]> Exchange(Fixture f, byte[] frame, bool rejected = false)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var client = new TcpClient(); await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, deadline.Token);
        var incoming = await listener.AcceptTcpClientAsync(deadline.Token);
        var server = LanProductControlResponder.AcceptWithBootstrapAsync<WebRtcProductPqcHandshakeCryptoProvider>(incoming,
            new("Fixture account", "NEBULA-FIXTURE", LocalId, "PC"),
            RemoteControlPairingMaterial.Create(LocalId, "PC", f.LocalKey.AsSpan(), new byte[1184]),
            () => f.Trusted, () => throw new InvalidOperationException("PIB incorrectly created MAIN crypto"),
            null, deadline.Token, f.Refresh(), f.Responder);
        await using var transport = new TcpProductControlTransport(client, 1024 * 1024, 1024 * 1024);
        await transport.SendAsync(frame, deadline.Token); var response = (await transport.ReadAsync(deadline.Token)).ToArray();
        if (rejected) await Reject(async () => await server, "userRejected");
        else Require(await server is LanIncomingControlResult.PairingExchangeCompleted, "PIB returned a MAIN session.");
        Require(await client.GetStream().ReadAsync(new byte[1], deadline.Token) == 0, "Bootstrap left its short connection open.");
        return response;
    }
    private static async Task TwoConnections()
    {
        var f = new Fixture();
        var candidate = LanPibWire.DecodeCandidate(await Exchange(f, LanPibWire.EncodeRequest(f.Request)));
        Require(f.Trusted.Length == 0 && f.Approvals == 0, "First short connection granted trust.");
        var confirm = f.Confirm(candidate);
        var ack = LanPibWire.DecodeFinalAck(await Exchange(f, LanPibWire.EncodeConfirm(confirm)));
        LanPibValidation.RequireFinalAckBindings(f.Request, candidate, confirm, ack, f.Clock.Now.ToUnixTimeMilliseconds());
        Require(f.Commits == 1 && f.Trusted.Single().DeviceId == PeerId, "Second connection did not publish the approved identity.");
    }
    private static async Task SocketRejection()
    {
        var f = new Fixture(); var candidate = f.Candidate(); f.Show = (_, _) => Task.FromResult(false);
        using var doc = JsonDocument.Parse(await Exchange(f, LanPibWire.EncodeConfirm(f.Confirm(candidate)), rejected: true));
        var failure = doc.RootElement.GetProperty("kemRefreshFailure");
        Require(failure.GetProperty("stage").GetString() == "identity_binding_confirm" &&
            failure.GetProperty("reasonCode").GetString() == "userRejected" && f.Commits == 0, "Refusal became successful trust.");
    }
    private static async Task FreshRefreshAuthority()
    {
        var f = new Fixture(); var refresh = f.Refresh();
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "skr3-golden.json")));
        var request = SignedLanKemRefreshWire.DecodeRequest(Encoding.UTF8.GetBytes("{\"kemRefreshRequest\":" +
            doc.RootElement.GetProperty("vectors")[0].GetProperty("request").GetRawText() + "}")) with
        {
            RequesterDeviceId = PeerId, RequesterProtocolIdentityFingerprint = f.Request.RequesterProtocolIdentityFingerprint,
            TargetDeviceId = LocalId, TargetProtocolIdentityFingerprint = Fingerprint(f.LocalKey), SentAt = f.Clock.Reference
        };
        try { _ = refresh.Respond(request, default); throw new InvalidOperationException("Unpaired requester refreshed keys."); }
        catch (LanKemRefreshRejectedException error) when (error.Code == "untrustedRequester") { }
        var candidate = f.Candidate(); _ = await f.Responder.ConfirmAsync(f.Confirm(candidate), default);
        var response = refresh.Respond(request, default);
        Require(response.ProtocolIdentityFingerprint == Fingerprint(f.LocalKey), "Newly approved authority was invisible to the same responder.");
    }

    private static async Task NativeFileScope()
    {
        var directory = Directory.CreateTempSubdirectory("skybridge-files-pib-");
        try
        {
            using var signer = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            var key = signer.ExportMLDsaPublicKey().ToImmutableArray();
            var fp = Fingerprint(key);
            using (var store = await RemoteControlIdentityStore.LoadOrCreateAsync(directory.FullName, "Files"))
            {
                foreach (var allow in new[] { false, true })
                {
                    var receiver = store.CreatePibResponder(new Approval((r, _) =>
                        Task.FromResult(r.SasCode.Length == 6 && allow)), () => { }, filesOnly: true);
                    var request = new LanPibRequest(3, Guid.NewGuid().ToString("D"), PeerId, store.PublicMaterial.DeviceId,
                        ["ML-DSA-65"], "ML-DSA-65", key, fp, [], Bytes(3, 24), LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow));
                    request = request with { RequesterSignature = signer.SignData(LanPibCanonical.RequestPreimage(request)).ToImmutableArray() };
                    var reply = receiver.CreateCandidate(request, default);
                    var confirm = Fixture.MakeConfirm(request, reply, LanProductControlMessages.Timestamp(DateTimeOffset.UtcNow));
                    confirm = confirm with { RequesterSignature = signer.SignData(LanPibCanonical.ConfirmPreimage(confirm)).ToImmutableArray() };
                    if (!allow) await Reject(() => receiver.ConfirmAsync(confirm, default), "userRejected");
                    else
                    {
                        var ack = await receiver.ConfirmAsync(confirm, default);
                        using var verify = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, reply.ProtocolIdentityPublicKey.AsSpan());
                        Require(ack.Accepted && verify.VerifyData(LanPibCanonical.FinalAckPreimage(ack), ack.ResponderSignature.AsSpan()),
                            "A file-pairing final ACK did not carry the real responder signature.");
                    }
                    Require(store.FileTransferPeers.Any(p => p.ProtocolPublicKeyFingerprint == fp) == allow &&
                        store.TrustedPeers.Count == 0 && store.TrustedMaterials.Count == 0,
                        "PIB admitted a declined file peer or granted unrelated controller authority.");
                }
            }
            using var reopened = await RemoteControlIdentityStore.LoadOrCreateAsync(directory.FullName, "Files");
            Require(reopened.FileTransferPeers.Single().ProtocolPublicKeyFingerprint == fp && reopened.TrustedPeers.Count == 0 &&
                reopened.FindWebRtcIdentity(PeerId, fp).Compared == null,
                "File-only pairing did not retain its permission boundary across restart.");
            Console.WriteLine("PASS native signed LAN file-only PIB rejects mismatch and reopens without controller authority");
        }
        finally { directory.Delete(true); }
    }

    internal static int NativeSignaturesVerified { get; private set; }
    internal static async Task NativeRoundTripWhenSupported()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Native identity storage requires Windows DPAPI; no substitute protector.
        }
        if (!MLDsa.IsSupported || !MLKem.IsSupported) throw new PlatformNotSupportedException("Windows PIB acceptance requires native PQC.");
        await NativeFileScope();
        var directory = Directory.CreateTempSubdirectory("skybridge-pib-native-");
        try
        {
            using var requester = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            var key = requester.ExportMLDsaPublicKey().ToImmutableArray();
            string localId;
            using (var store = await RemoteControlIdentityStore.LoadOrCreateAsync(directory.FullName, "PIB native test"))
            {
                localId = store.PublicMaterial.DeviceId;
                var responder = store.CreatePibResponder(new Approval((_, _) => Task.FromResult(true)), () => { });
                var request = new LanPibRequest(3, Guid.NewGuid().ToString("D"), PeerId, localId, ["ML-DSA-65"], "ML-DSA-65",
                    key, Fingerprint(key), [], Bytes(1, 24), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0);
                request = request with { RequesterSignature = requester.SignData(LanPibCanonical.RequestPreimage(request)).ToImmutableArray() };
                var candidate = responder.CreateCandidate(LanPibWire.DecodeRequest(LanPibWire.EncodeRequest(request)), default);
                using var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, candidate.ProtocolIdentityPublicKey.AsSpan());
                Require(verifier.VerifyData(LanPibCanonical.CandidatePreimage(candidate), candidate.Signature.AsSpan()), "Native candidate signature failed.");
                NativeSignaturesVerified += 2; // production requester verify plus independent response verify
                var confirm = Fixture.MakeConfirm(request, candidate, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0);
                confirm = confirm with { RequesterSignature = requester.SignData(LanPibCanonical.ConfirmPreimage(confirm)).ToImmutableArray() };
                await Reject(() => responder.ConfirmAsync(confirm with { RequesterSignature = Bytes(0, 3309) }, default), "signatureInvalid");
                var ack = await responder.ConfirmAsync(LanPibWire.DecodeConfirm(LanPibWire.EncodeConfirm(confirm)), default);
                Require(verifier.VerifyData(LanPibCanonical.FinalAckPreimage(ack), ack.ResponderSignature.AsSpan()), "Native final ACK signature failed.");
                NativeSignaturesVerified += 2;
                Require(store.TrustedPeers.Single().ProtocolPublicKeyFingerprint == Fingerprint(key), "Native final ACK preceded actual trust persistence.");
            }
            using var reopened = await RemoteControlIdentityStore.LoadOrCreateAsync(directory.FullName, "PIB native test");
            Require(reopened.PublicMaterial.DeviceId == localId && reopened.TrustedPeers.Single().ProtocolPublicKeyFingerprint == Fingerprint(key),
                "Native pairing did not survive identity-store restart.");
        }
        finally { directory.Delete(recursive: true); }
    }
}
