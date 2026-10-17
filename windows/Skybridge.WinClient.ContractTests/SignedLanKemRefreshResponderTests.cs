using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;
using Canonical = Skybridge.WinClient.Services.SignedLanKemRefreshCanonical;
using Wire = Skybridge.WinClient.Services.SignedLanKemRefreshWire;

internal static class SignedLanKemRefreshResponderTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("SKR responder signs the actual supported v3 intersection and original bindings", FullIntersection),
        ("SKR replies stay within an Android authority containing only the requested ID", NoAliasExpansion),
        ("SKR responder excludes mismatched Q and signs a valid empty v3 intersection", MismatchedProfile),
        ("SKR responder preserves distinct v1 and v2 fields without advertising X-Wing", LegacyVersions),
        ("SKR responder rejects unknown IDs conflicting pins and ambiguous existing aliases", AuthorityBindings),
        ("SKR responder preserves raw requested identity spelling in its canonical hash", OriginalRequest),
        ("SKR responder rejects invented inventory and invalid native policy metadata", InvalidInventory),
        ("SKR completed retry preserves exact signed bytes generation and expiration", CompletedRetry),
        ("SKR failed signing remains replay-blocked without a cached success", FailedSigning),
        ("SKR rate limits include completed retries and expire on elapsed time", RateLimit),
        ("SKR finite cache rejects capacity pressure without evicting admitted responses", Capacity),
        ("SKR pending duplicate cannot cause another sign and cancellation awaits actual work", PendingCancellation),
        ("SKR account revocation blocks signing cached replies and final send admission", Revocation),
        ("SKR elapsed signing and wall rollback cannot publish a stale generation", ClockChanges),
        ("SKR key ID uses the independent Apple domain and little endian key framing", KeyIdGolden),
        ("MAIN bootstrap writes exactly one SKR reply and closes without creating crypto", () => SocketReply(false)),
        ("MAIN bootstrap retains the bounded one MiB JSON contract beyond handshake size", () => SocketReply(true)),
        ("MAIN bootstrap returns a diagnostic for paired identity rejection without admitting MAIN", SocketRejection),
        ("MAIN bootstrap rejects malformed JSON and oversized prefix before crypto", MalformedSocket),
        ("MAIN listener retains a canceled noncooperative signing worker until actual completion", ListenerCancellation)
    ];
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Reject(Action action, string? code = null)
    {
        try { action(); }
        catch (LanKemRefreshRejectedException error) when (code is null || error.Code == code) { return; }
        catch (Exception error) when (code is null && error is InvalidDataException or InvalidOperationException or OperationCanceledException) { return; }
        throw new InvalidOperationException("Expected bounded SKR rejection was not observed: " + code);
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_800_000_000_000);
        private long _ticks;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        internal void Advance(TimeSpan interval) { Now += interval; _ticks += interval.Ticks; }
    }
    private sealed class Fixture
    {
        internal Clock Clock { get; } = new();
        internal LanKemRefreshInventory Inventory { get; }
        internal LanKemRefreshRequest Request { get; }
        internal RemoteControlTrustedPeer[] Trusted { get; }
        internal SignedLanKemRefreshResponder Responder { get; }
        internal bool Current = true;
        internal int Signs;
        internal Func<byte[], ImmutableArray<byte>>? Signing;
        internal Fixture()
        {
            using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "skr3-golden.json")));
            var vector = doc.RootElement.GetProperty("vectors")[0];
            var response = Wire.DecodeResponse(Encoding.UTF8.GetBytes("{\"signedKEMRefresh\":" + vector.GetProperty("response").GetRawText() + "}"));
            Request = Wire.DecodeRequest(Encoding.UTF8.GetBytes("{\"kemRefreshRequest\":" + vector.GetProperty("request").GetRawText() + "}")) with
            { SentAt = Clock.Now.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0 };
            Inventory = new(response.DeviceId, response.ProtocolIdentityPublicKey,
                response.KemPublicKeys.Where(k => k.SuiteWireId != 1).ToImmutableArray(), "windows", "Windows 10.0.26100", response.QPeriaptAuthProfile!);
            Trusted = [new(Request.RequesterDeviceId, Request.RequesterProtocolIdentityFingerprint!)];
            Responder = New(Trusted);
        }
        internal SignedLanKemRefreshResponder New(IReadOnlyCollection<RemoteControlTrustedPeer> peers) =>
            new(Inventory, peers, bytes => { Interlocked.Increment(ref Signs); return Signing?.Invoke(bytes) ?? SHA256.HashData(bytes).ToImmutableArray(); },
                () => { if (!Current) throw new InvalidOperationException("fixture account revoked"); }, Clock);
        internal LanKemRefreshRequest Fresh(int n) => Request with
        { SentAt = Clock.Now.ToUnixTimeMilliseconds() / 1000.0 - 978307200.0, Nonce = SHA256.HashData(BitConverter.GetBytes(n)).ToImmutableArray() };
        internal LanSignedKemRefresh Send(LanKemRefreshRequest? request = null) => Responder.Respond(request ?? Request, default);
    }
    private static Task FullIntersection()
    {
        var f = new Fixture(); var reply = f.Send();
        Require(reply.KemPublicKeys.Select(k => k.SuiteWireId).SequenceEqual(new[] { 18, 257 }) &&
            reply.PermittedSuiteWireIds!.Value.SequenceEqual(new[] { 18, 257 }), "Inventory was invented or intersection omitted.");
        Require(reply.QPeriaptAuthProfile == f.Inventory.QAuthProfile && reply.Platform == "windows", "Actual local metadata was lost.");
        Require(reply.Signature.AsSpan().SequenceEqual(SHA256.HashData(Canonical.ResponsePreimage(reply))), "Signer did not receive exact canonical response.");
        Canonical.RequireResponseBindings(f.Request, reply, f.Request.TargetProtocolIdentityFingerprint!, f.Clock.Now.ToUnixTimeMilliseconds());
        _ = Wire.DecodeResponse(Wire.EncodeResponse(reply)); return Task.CompletedTask;
    }
    private static Task NoAliasExpansion()
    {
        foreach (var bare in new[] { false, true })
        {
            var f = new Fixture(); var request = f.Request with { TargetDeviceId = bare ? f.Request.TargetDeviceId[3..] : f.Request.TargetDeviceId };
            var response = f.Send(request);
            // Android SignedLanKemRefreshClient checks every signed identifier against
            // trustedIds after verification; a canonical-only or bare-only authority is legal.
            var trustedIds = new HashSet<string>(StringComparer.Ordinal) { request.TargetDeviceId };
            Require(response.Aliases.Append(response.DeviceId).All(trustedIds.Contains), "SKR attempted to expand Android's existing alias authority.");
        }
        return Task.CompletedTask;
    }
    private static Task MismatchedProfile()
    {
        var f = new Fixture(); var request = f.Request with { QPeriaptAuthProfile = f.Inventory.QAuthProfile.Replace("/7/", "/8/", StringComparison.Ordinal) };
        Require(f.Send(request).KemPublicKeys.Select(k => k.SuiteWireId).SequenceEqual(new[] { 257 }), "Profile mismatch did not exclude only Q.");
        request = request with { RequestedSuiteWireIds = [18] };
        var empty = f.Send(request);
        Require(empty.KemPublicKeys.IsEmpty && !empty.Signature.IsEmpty && empty.PermittedSuiteWireIds!.Value.Length == 2, "Empty intersection was fabricated as a transport failure or success key.");
        return Task.CompletedTask;
    }
    private static Task LegacyVersions()
    {
        foreach (var version in new[] { 1, 2 })
        {
            var f = new Fixture(); var request = f.Request with { Version = version, PolicyHashHex = Canonical.PolicyHash(version),
                RequestedSuiteWireIds = version == 1 ? [1, 257] : [18], Platform = null, OsVersion = null, QPeriaptAuthProfile = null };
            var reply = f.Send(request);
            Require(reply.KemPublicKeys.Length == 1 && reply.KemPublicKeys[0].SuiteWireId == (version == 1 ? 257 : 18) &&
                reply.PermittedSuiteWireIds is null && reply.QPeriaptAuthProfile is null && (reply.Platform is null) == (version == 1), "Legacy wire fields changed.");
        }
        var v1 = new Fixture(); Reject(() => v1.Send(v1.Request with { Version = 1, PolicyHashHex = Canonical.PolicyHash(1),
            RequestedSuiteWireIds = [1], Platform = null, OsVersion = null, QPeriaptAuthProfile = null }), "noCommonSuite");
        return Task.CompletedTask;
    }
    private static Task AuthorityBindings()
    {
        var f = new Fixture();
        foreach (var bad in new[] { f.Request with { RequesterDeviceId = "id:unpaired-device" },
            f.Request with { RequesterProtocolIdentityFingerprint = new string('f', 64) } }) Reject(() => f.Send(bad), "untrustedRequester");
        foreach (var bad in new[] { f.Request with { TargetDeviceId = "id:another-target" }, f.Request with { TargetProtocolIdentityFingerprint = null },
            f.Request with { TargetProtocolIdentityFingerprint = new string('b', 64) } }) Reject(() => f.Send(bad), "targetIdentityMismatch");
        var ambiguous = f.New([f.Trusted[0], new("id:another-peer", f.Trusted[0].ProtocolPublicKeyFingerprint, [f.Request.RequesterDeviceId])]);
        Reject(() => ambiguous.Respond(f.Request, default), "untrustedRequester");
        Require(f.Signs == 0, "An unauthoritative request reached the signer."); return Task.CompletedTask;
    }
    private static Task OriginalRequest()
    {
        var f = new Fixture(); var request = f.Request with { RequesterDeviceId = f.Request.RequesterDeviceId[3..].ToUpperInvariant(),
            TargetDeviceId = f.Request.TargetDeviceId[3..].ToUpperInvariant() };
        var reply = f.Send(request);
        Require(reply.RequestHashHex == Canonical.RequestHash(request) && reply.RequestHashHex != Canonical.RequestHash(f.Request), "Lookup normalization rewrote signed input.");
        Require(reply.DeviceId == request.TargetDeviceId && reply.Aliases.IsEmpty, "Requested target spelling was lost or alias authority was expanded.");
        var alias = f.New([f.Trusted[0] with { KnownDeviceIds = ["id:existing-alias"] }]);
        _ = alias.Respond(f.Fresh(1) with { RequesterDeviceId = "existing-alias" }, default);
        return Task.CompletedTask;
    }
    private static Task InvalidInventory()
    {
        var f = new Fixture();
        foreach (var inventory in new[] { f.Inventory with { Keys = [f.Inventory.Keys[0]] }, f.Inventory with { QAuthProfile = "unverified" },
            f.Inventory with { OsVersion = "Windows 10.0.10000" }, f.Inventory with { Keys = [f.Inventory.Keys[0], new(1, new byte[1216].ToImmutableArray())] } })
            Reject(() => new SignedLanKemRefreshResponder(inventory, f.Trusted, _ => [], () => { }));
        return Task.CompletedTask;
    }
    private static Task CompletedRetry()
    {
        var f = new Fixture(); var first = f.Send(); f.Clock.Advance(TimeSpan.FromSeconds(7)); var second = f.Send();
        Require(f.Signs == 1 && Wire.EncodeResponse(first).SequenceEqual(Wire.EncodeResponse(second)), "Retry renewed or re-signed the response.");
        f.Clock.Advance(TimeSpan.FromSeconds(114)); Reject(() => f.Send());
        Require(f.Signs == 1, "Stale request was re-signed."); return Task.CompletedTask;
    }
    private static Task FailedSigning()
    {
        var f = new Fixture { Signing = _ => throw new InvalidOperationException("fixture signing failure") };
        Reject(() => f.Send()); f.Signing = null; Reject(() => f.Send(), "replay");
        Require(f.Signs == 1, "Failed signing was represented as a reusable successful reply.");
        f.Clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromMilliseconds(1)); _ = f.Send(f.Fresh(2));
        Require(f.Signs == 2, "Expired failed admission prevented a fresh independent request."); return Task.CompletedTask;
    }
    private static Task RateLimit()
    {
        var f = new Fixture(); for (var i = 0; i < 10; i++) _ = f.Send(); Reject(() => f.Send(), "rateLimited");
        Require(f.Signs == 1, "Retries re-signed instead of using exact cache.");
        f.Clock.Advance(TimeSpan.FromSeconds(60)); Reject(() => f.Send(), "rateLimited");
        f.Clock.Advance(TimeSpan.FromMilliseconds(1)); _ = f.Send(); return Task.CompletedTask;
    }
    private static Task Capacity()
    {
        var f = new Fixture(); var peers = Enumerable.Range(0, 32).Select(i => new RemoteControlTrustedPeer("id:trusted-peer-" + i,
            f.Request.RequesterProtocolIdentityFingerprint!)).ToArray(); var responder = f.New(peers);
        for (var i = 0; i < 256; i++) _ = responder.Respond(f.Fresh(i) with { RequesterDeviceId = peers[i % 32].DeviceId }, default);
        Reject(() => responder.Respond(f.Fresh(300) with { RequesterDeviceId = peers[0].DeviceId }, default), "capacityReached");
        _ = responder.Respond(f.Fresh(0) with { RequesterDeviceId = peers[0].DeviceId }, default);
        Require(f.Signs == 256, "Capacity pressure evicted a valid response or invoked signing.");
        f.Clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromMilliseconds(1));
        _ = responder.Respond(f.Fresh(301) with { RequesterDeviceId = peers[0].DeviceId }, default); return Task.CompletedTask;
    }
    private static async Task PendingCancellation()
    {
        var f = new Fixture(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        using var cancel = new CancellationTokenSource();
        f.Signing = bytes => { entered.Set(); if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("fixture release missing"); return SHA256.HashData(bytes).ToImmutableArray(); };
        var work = Task.Run(() => f.Responder.Respond(f.Request, cancel.Token));
        try
        {
            Require(entered.Wait(TimeSpan.FromSeconds(3)), "Sign did not enter."); Reject(() => f.Send(), "replay");
            cancel.Cancel(); Require(!work.IsCompleted, "Cancellation detached actual signing work.");
        }
        finally { release.Set(); }
        try { await work; throw new InvalidOperationException("Canceled sign returned a response."); } catch (OperationCanceledException) { }
        Require(f.Signs == 1, "Pending duplicate signed again."); Reject(() => f.Send(), "replay");
    }
    private static Task Revocation()
    {
        var f = new Fixture(); var reply = f.Send(); f.Current = false;
        Reject(() => f.Send()); Reject(() => f.Responder.RequireSend(f.Request, reply, default));
        Require(f.Signs == 1, "Revoked cache hit reached signing.");
        var during = new Fixture(); during.Signing = bytes => { during.Current = false; return SHA256.HashData(bytes).ToImmutableArray(); };
        Reject(() => during.Send()); return Task.CompletedTask;
    }
    private static Task ClockChanges()
    {
        var f = new Fixture(); _ = f.Send(); f.Clock.Now -= TimeSpan.FromMilliseconds(1); Reject(() => f.Send(), "clockRollback");
        var slow = new Fixture(); slow.Signing = bytes => { slow.Clock.Advance(TimeSpan.FromMinutes(6)); return SHA256.HashData(bytes).ToImmutableArray(); };
        Reject(() => slow.Send()); Require(slow.Signs == 1, "Slow signer was retried."); return Task.CompletedTask;
    }
    private static Task KeyIdGolden()
    {
        // Independently generated from the existing shared public vector by Python hashlib/struct.
        var f = new Fixture(); var id = SignedLanKemRefreshResponder.KeyId(f.Request.TargetProtocolIdentityFingerprint!, f.Inventory.Keys);
        Require(id == "skr1-d03815179f72-cf97aed2ebb87dff", "Apple key ID domain/order/length framing differs."); return Task.CompletedTask;
    }
    // Controlled signer uses SHA-256 bytes to expose the signed preimage. It is not
    // a native ML-DSA implementation or a valid production signature.
    private sealed class NeverCrypto : IProductHandshakeCryptoProvider, IDisposable
    {
        public ValueTask<WebRtcProductHandshakeMessageA> CreateInitiatorMessageAAsync(ProductHandshakePeerContext c, CancellationToken t = default) => throw new InvalidOperationException();
        public ValueTask<WebRtcProductHandshakeResponderMaterial> CreateResponderMessageBAsync(ProductHandshakePeerContext c, WebRtcProductHandshakeMessageA a, ReadOnlyMemory<byte> h, CancellationToken t = default) => throw new InvalidOperationException();
        public ValueTask<ProductHandshakeSharedSecret> OpenResponderMessageBAsync(ProductHandshakePeerContext c, WebRtcProductHandshakeMessageA a, ReadOnlyMemory<byte> h, WebRtcProductHandshakeMessageB b, CancellationToken t = default) => throw new InvalidOperationException();
        public void AbortInitiatorSecret(ReadOnlyMemory<byte> h) => throw new InvalidOperationException();
        public void Dispose() => throw new InvalidOperationException("Bootstrap must not create handshake crypto.");
    }
    private sealed class SocketFixture : IAsyncDisposable
    {
        internal Fixture F { get; } = new();
        internal CancellationTokenSource Deadline { get; } = new(TimeSpan.FromSeconds(5));
        internal TcpProductControlTransport Remote { get; }
        internal TcpClient Client { get; }
        internal Task<LanIncomingControlResult> Accept { get; }
        internal int CryptoCreated;
        internal SocketFixture(TcpClient client, TcpClient accepted)
        {
            Client = client; Remote = new(client, Wire.MaximumBytes, Wire.MaximumBytes);
            Accept = AcceptPeer(accepted, F, Deadline.Token, () => { CryptoCreated++; return new NeverCrypto(); });
        }
        internal static async Task<SocketFixture> Open()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var client = new TcpClient(); await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            return new(client, await listener.AcceptTcpClientAsync());
        }
        public async ValueTask DisposeAsync()
        {
            Deadline.Cancel(); await Remote.DisposeAsync();
            try { await Accept; } catch (Exception error) when (error is IOException or InvalidDataException or JsonException or OperationCanceledException) { }
            Deadline.Dispose();
        }
    }
    private static Task<LanIncomingControlResult> AcceptPeer(TcpClient accepted, Fixture f, CancellationToken token, Func<NeverCrypto> crypto)
    {
        var key = f.Inventory.Keys.Single(k => k.SuiteWireId == 257).PublicKey;
        return LanProductControlResponder.AcceptWithBootstrapAsync(accepted,
            new("Fixture account", "NEBULA-TEST", f.Inventory.DeviceId, "Fixture"),
            RemoteControlPairingMaterial.Create(f.Inventory.DeviceId, "Fixture", f.Inventory.SigningPublicKey.AsSpan(), key.AsSpan()),
            f.Trusted, crypto, null, token, f.Responder);
    }
    private static async Task SocketReply(bool padded)
    {
        await using var f = await SocketFixture.Open(); var bytes = Wire.EncodeRequest(f.F.Request);
        if (padded) bytes = Encoding.UTF8.GetBytes(new string(' ', 20_000)).Concat(bytes).ToArray();
        await f.Remote.SendAsync(bytes, f.Deadline.Token);
        var reply = Wire.DecodeResponse((await f.Remote.ReadAsync(f.Deadline.Token)).Span);
        Require(await f.Accept is LanIncomingControlResult.KemRefreshCompleted && f.CryptoCreated == 0, "Bootstrap became MAIN or created crypto.");
        Canonical.RequireResponseBindings(f.F.Request, reply, f.F.Request.TargetProtocolIdentityFingerprint!, f.F.Clock.Now.ToUnixTimeMilliseconds());
        Require(await f.Client.GetStream().ReadAsync(new byte[1], f.Deadline.Token) == 0, "One-shot bootstrap socket remained open.");
    }
    private static async Task SocketRejection()
    {
        await using var f = await SocketFixture.Open(); var request = f.F.Request with { RequesterDeviceId = "id:unpaired-device" };
        await f.Remote.SendAsync(Wire.EncodeRequest(request), f.Deadline.Token);
        using var response = JsonDocument.Parse(await f.Remote.ReadAsync(f.Deadline.Token));
        var failure = response.RootElement.GetProperty("kemRefreshFailure");
        Require(failure.GetProperty("stage").GetString() == "kem_refresh" && failure.GetProperty("reasonCode").GetString() == "untrustedRequester" &&
            failure.GetProperty("requestHashHex").GetString() == Canonical.RequestHash(request), "Incorrect diagnostic envelope.");
        try { await f.Accept; throw new InvalidOperationException("Rejected requester returned successful admission."); }
        catch (LanKemRefreshRejectedException error) when (error.Code == "untrustedRequester") { }
        Require(f.CryptoCreated == 0 && f.F.Signs == 0, "Rejected requester created crypto/signature.");
    }
    private static async Task MalformedSocket()
    {
        foreach (var mode in new[] { 0, 1, 2 })
        {
            await using var f = await SocketFixture.Open();
            if (mode == 0)
            {
                var header = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(header, Wire.MaximumBytes + 1);
                await f.Client.GetStream().WriteAsync(header, f.Deadline.Token);
            }
            else await f.Remote.SendAsync(Encoding.UTF8.GetBytes(mode == 1 ? "{\"kemRefreshRequest\":{},\"identity\":{}}" : "{\"identity\":{}}"), f.Deadline.Token);
            try { await f.Accept; throw new InvalidOperationException("Invalid bootstrap admitted."); }
            catch (Exception error) when (error is JsonException or InvalidDataException) { }
            Require(f.CryptoCreated == 0 && f.F.Signs == 0, "Malformed first frame reached crypto.");
        }
    }
    private static async Task ListenerCancellation()
    {
        var f = new Fixture(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        f.Signing = bytes => { entered.Set(); if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("fixture sign release missing"); return SHA256.HashData(bytes).ToImmutableArray(); };
        await using var listener = new LanProductControlListener(async (client, token) => { _ = await AcceptPeer(client, f, token, () => throw new InvalidOperationException("Unexpected crypto")); }, () => f.Current);
        listener.Start(IPAddress.Loopback, default);
        using var client = new TcpClient(); await client.ConnectAsync((IPEndPoint)listener.RequireLiveListener().LocalEndpoint);
        await using var remote = new TcpProductControlTransport(client, Wire.MaximumBytes, Wire.MaximumBytes);
        await remote.SendAsync(Wire.EncodeRequest(f.Request), default);
        Task stop;
        try
        {
            Require(entered.Wait(TimeSpan.FromSeconds(3)), "Listener did not own signer.");
            stop = listener.StopAsync(); Require(!stop.IsCompleted, "Listener detached noncooperative signer.");
            Require(listener.ReadSnapshot().ActiveConnections == 1, "Signing owner disappeared before completion.");
        }
        finally { release.Set(); }
        await stop;
        Require(listener.ReadSnapshot().ActiveConnections == 0 && f.Signs == 1, "Listener did not drain exact signer owner.");
    }
}
