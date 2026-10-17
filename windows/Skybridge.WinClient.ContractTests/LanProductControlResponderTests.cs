using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Net;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.RemoteControl;
using System.Net.Sockets;
using Skybridge.WinClient.Services;

internal static class LanProductControlResponderTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("MAIN admission survives the first heartbeat interval while awaiting peer approval", DelayedAdmission),
        ("incoming MAIN requires Finished and ordered identity approval before audio binding", () => IncomingAdmission(false)),
        ("bootstrap-enabled MAIN preserves Finished ordered admission and encrypted audio handoff", () => IncomingAdmission(true)),
        ("incoming MAIN rejects unknown pins wrong targets and absent SOA before crypto", UntrustedInitiator),
        ("bootstrap listener still rejects binary MAIN before the first approved pairing", NoApprovedPairing),
        ("incoming MAIN invalid Finished never sends product identity", InvalidFinished),
        ("incoming MAIN rejects conflicting product identity after Finished", WrongProductIdentity),
        ("incoming MAIN rejects an oversized prefix without waiting for its body", OversizedPrefix),
        ("incoming MAIN cancellation closes its actual pending socket", CanceledInitialRead),
        ("incoming MAIN crypto cleanup failure cannot return a session", CryptoCleanupFailure),
        ("incoming MAIN preserves handshake failure together with failed crypto release", HandshakeAndCleanupFailure),
        ("incoming MAIN rejects unimplemented bootstrap without granting trust", BootstrapRejected),
        ("incoming MAIN enforces its smaller bound while waiting for Finished", OversizedFinished),
        ("MAIN publishes file reception only with an actual nonzero listener port", LocalCapabilities)
    ];
    private const string LocalId = "id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string PeerId = "11111111-2222-3333-4444-555555555555";
    private static readonly byte[] LocalPublicKey = Enumerable.Repeat((byte)31, 1952).ToArray();
    private static readonly byte[] PeerPublicKey = Enumerable.Repeat((byte)47, 1952).ToArray();
    private static WebRtcProductProtocolIdentityPublicKey Signing(byte[] key) => new(WebRtcProductSignatureAlgorithm.MlDsa65, key);
    private static LanProductIdentity Identity(string id, byte[] key) => new(id, [new(0x0101, new byte[1184])], 100,
        [new("ML-DSA-65", key)], DeviceName: "Fixture", Capabilities: []);
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }

    private static async Task DelayedAdmission()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var remoteClient = new TcpClient();
        await remoteClient.ConnectAsync((IPEndPoint)listener.LocalEndpoint, deadline.Token);
        using var localClient = await listener.AcceptTcpClientAsync(deadline.Token);
        await using var remote = new TcpProductControlTransport(remoteClient, 1024 * 1024, 1024 * 1024);
        await using var local = new TcpProductControlTransport(localClient, 1024 * 1024, 1024 * 1024);
        using var keys = new ProductSessionKeys(ProductHandshakeRole.Responder, "approval-wait", new byte[32],
            Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 32).ToArray());
        using var reversed = new ProductSessionKeys(ProductHandshakeRole.Initiator, keys.SessionId, keys.TranscriptHash, keys.ReceiveKey, keys.SendKey);
        using var remoteKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(reversed);
        await using var session = new LanProductControlSession(local, keys,
            new(RemoteControlHandshakeBinding.CanonicalDeviceId(PeerId), Signing(PeerPublicKey).AuthoritativeFingerprint),
            Identity(LocalId, LocalPublicKey), new(SkyBridgeProtocolConstants.TcpControlDnsSdService,
                "fixture.local", 1234, "fixture._skybridge._tcp.local", "resolved-dns-sd-endpoint"),
            IPAddress.Loopback, deadline.Token,
            ProductHandshakeProtocolIdentity.Capture(Signing(LocalPublicKey).Encode(), "fixture"),
            ProductHandshakeProtocolIdentity.Capture(Signing(PeerPublicKey).Encode(), "fixture"), ReadOnlyMemory<byte>.Empty);
        var admission = session.CompleteAdmissionAsync(deadline.Token);
        try
        {
            async Task<LanControlMessage> Read() => LanProductControlMessages.Decode(
                WebRtcControlChannelCodec.DecryptAppleLegacyAppPayload(
                    ProductControlTrafficPadding.Unwrap((await remote.ReadAsync(deadline.Token)).ToArray()), remoteKeys));
            Require((await Read()).Kind == LanControlMessageKind.Identity, "Missing local identity.");
            var ping = LanProductControlMessages.Payload<LanProductPing>(await Read());
            var elapsed = Task.Delay(TimeSpan.FromSeconds(22), deadline.Token);
            if (await Task.WhenAny(session.Completion, elapsed) == session.Completion)
                throw new InvalidOperationException("MAIN ended before its 60-second admission deadline.", await session.Completion);
            await elapsed;
            Require(!session.IsReady && !admission.IsCompleted, "Waiting for approval prematurely admitted MAIN.");
            foreach (var plaintext in new[] {
                LanProductControlMessages.Encode(LanControlMessageKind.Identity, Identity(PeerId, PeerPublicKey)),
                LanProductControlMessages.Encode(LanControlMessageKind.Pong, ping) })
                await remote.SendAsync(ProductControlTrafficPadding.Wrap(
                    WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(plaintext, remoteKeys)), deadline.Token);
            await admission;
            Require(session.IsReady, "A delayed valid peer approval did not admit MAIN.");
        }
        finally
        {
            deadline.Cancel();
            try { await admission; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
            catch (IOException) when (session.Completion.IsCompleted) { }
        }
    }
    private static readonly byte[] Secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
    private static RemoteControlPairingMaterial Pairing => RemoteControlPairingMaterial.Create(LocalId, "Fixture", LocalPublicKey, new byte[1184]);
    private static RemoteControlSecurityIdentity Account => new("Test account", "NEBULA-TEST", LocalId, "Fixture");
    private static RemoteControlTrustedPeer[] Trusted => [new(PeerId, Signing(PeerPublicKey).AuthoritativeFingerprint)];
    private static byte[] Soa(string target = LocalId) => new RemoteControlHandshakeSoa(
        RemoteControlHandshakeBinding.PeerId(PeerId), RemoteControlHandshakeBinding.PeerId(target), new byte[16]).EncodeTlv();
    private static WebRtcProductHandshakeMessageA MessageA(byte[]? extensions = null, byte[]? key = null) => new(
        [0x0101], [new(0x0101, new byte[1088])], new byte[32],
        new(["ML-KEM-768"], ["ML-DSA-65"], ["pqc"], ["AES-256-GCM"], false, "controlled-test-crypto", "liboqs"),
        WebRtcProductHandshakePolicy.Default, Signing(key ?? PeerPublicKey).Encode(), extensions ?? Soa(), new byte[] { 1 });

    // This provider deliberately replaces native signature/KEM operations. TCP framing,
    // SOA/pin checks, transcript KDF, both FIN1 MACs, encrypted admission, and cleanup are real.
    private sealed class Crypto : IProductHandshakeCryptoProvider, IDisposable
    {
        internal bool WasDisposed, ThrowOnDispose;
        public ValueTask<WebRtcProductHandshakeResponderMaterial> CreateResponderMessageBAsync(ProductHandshakePeerContext context,
            WebRtcProductHandshakeMessageA a, ReadOnlyMemory<byte> hash, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var b = new WebRtcProductHandshakeMessageB(0x0101, Array.Empty<byte>(), new byte[32],
                new(0x0101, Array.Empty<byte>(), new byte[12], new byte[] { 1 }, new byte[16]),
                Signing(LocalPublicKey).Encode(), new byte[] { 1 });
            return ValueTask.FromResult(new WebRtcProductHandshakeResponderMaterial(b, Secret));
        }
        public ValueTask<WebRtcProductHandshakeMessageA> CreateInitiatorMessageAAsync(ProductHandshakePeerContext context,
            CancellationToken cancellationToken = default) => throw new InvalidOperationException("Responder-only fixture.");
        public ValueTask<ProductHandshakeSharedSecret> OpenResponderMessageBAsync(ProductHandshakePeerContext context,
            WebRtcProductHandshakeMessageA a, ReadOnlyMemory<byte> hash, WebRtcProductHandshakeMessageB b,
            CancellationToken cancellationToken = default) => throw new InvalidOperationException("Responder-only fixture.");
        public void AbortInitiatorSecret(ReadOnlyMemory<byte> hash) => throw new InvalidOperationException("Responder-only fixture.");
        public void Dispose() { WasDisposed = true; if (ThrowOnDispose) throw new IOException("fixture crypto cleanup"); }
    }

    private sealed class Incoming : IAsyncDisposable
    {
        internal CancellationTokenSource Deadline { get; } = new(TimeSpan.FromSeconds(10));
        internal TcpClient Client { get; }
        internal TcpProductControlTransport Remote { get; }
        internal Task<LanProductControlSession> Accept { get; }
        internal Crypto Provider { get; } = new();
        internal int CryptoCreations;
        internal int TrustReads;
        internal RemoteControlTrustedPeer[] PublishedTrusted = [];
        internal ProductSessionKeys? Keys;
        internal WebRtcAppSecureSessionKeys? AppKeys;
        private Incoming(TcpClient client, TcpClient accepted, bool bootstrap)
        {
            Client = client; Remote = new(client, 1024 * 1024, 1024 * 1024);
            Accept = Admit();
            async Task<LanProductControlSession> Admit()
            {
                Crypto Create() { CryptoCreations++; return Provider; }
                if (!bootstrap) return await LanProductControlResponder.AcceptAsync(accepted, Account, Pairing, Trusted, Create, null, Deadline.Token);
                var profile = "q-periapt-abi2-policy-v1/" + new string('1', 64) + "/" + new string('2', 64) + "/7/" + new string('3', 64);
                var inventory = new LanKemRefreshInventory(LocalId, LocalPublicKey.ToImmutableArray(),
                    [new(18, new byte[1216].ToImmutableArray()), new(257, new byte[1184].ToImmutableArray())], "windows", "Windows 10.0.26100", profile);
                var refresh = new SignedLanKemRefreshResponder(inventory, () => PublishedTrusted,
                    _ => throw new InvalidOperationException("MessageA must not enter SKR signing."), () => { });
                var pairing = new LanPibResponder(new(LocalId, "Fixture", LocalPublicKey.ToImmutableArray()),
                    _ => throw new InvalidOperationException("MessageA must not enter PIB signing."),
                    (_, _, _) => throw new InvalidOperationException("MessageA must not enter PIB verification."),
                    _ => throw new InvalidOperationException("MessageA must not enter PIB preflight."),
                    (_, _, _) => throw new InvalidOperationException("MessageA must not enter PIB commit."), new UnusedApproval(), () => { });
                var result = await LanProductControlResponder.AcceptWithBootstrapAsync(accepted, Account, Pairing,
                    () => { TrustReads++; return PublishedTrusted; }, Create, null, Deadline.Token, refresh, pairing);
                return result is LanIncomingControlResult.Main main ? main.Session : throw new InvalidOperationException("MessageA was treated as SKR.");
            }
        }
        internal static async Task<Incoming> Open(bool bootstrap = false)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var client = new TcpClient();
            await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
            return new(client, await listener.AcceptTcpClientAsync(), bootstrap);
        }
        internal async Task BeginHandshake(bool padded = false)
        {
            PublishedTrusted = Trusted;
            var a = MessageA(); var frame = a.Encode();
            if (padded) frame = WebRtcProductHandshakeCodec.WrapHandshakePadding(frame, frame.Length + 37);
            await Remote.SendAsync(frame, Deadline.Token);
            ReadOnlyMemory<byte> response;
            try { response = await Remote.ReadAsync(Deadline.Token); }
            catch (IOException wireFailure)
            {
                try { await Accept; }
                catch (Exception acceptFailure) { throw new AggregateException("Responder and peer read failed.", acceptFailure, wireFailure); }
                throw;
            }
            var b = WebRtcProductHandshakeCodec.DecodeMessageB(response.Span);
            Keys = ProductHandshakeKeyDerivation.Derive(Secret, b.SelectedSuiteWireId,
                SHA256.HashData(a.EncodeWithoutSignature()), SHA256.HashData(b.EncodeWithoutSignature()),
                a.ClientNonce.Span, b.ServerNonce.Span, ProductHandshakeRole.Initiator);
            var finished = WebRtcProductHandshakeCodec.DecodeFinished((await Remote.ReadAsync(Deadline.Token)).Span);
            Require(ProductHandshakeKeyDerivation.VerifyFinished(finished, Keys, ProductHandshakeRole.Responder), "Responder FIN1 is invalid.");
            AppKeys = WebRtcProductHandshakeSessionKeys.ToWebRtcKeys(Keys);
        }
        internal Task Finish(bool corrupt = false)
        {
            var bytes = ProductHandshakeKeyDerivation.CreateFinished(Keys ?? throw new InvalidOperationException()).Encode();
            if (corrupt) bytes[^1] ^= 1;
            return Remote.SendAsync(bytes, Deadline.Token);
        }
        internal async Task<LanControlMessage> Read() => LanProductControlMessages.Decode(
            WebRtcControlChannelCodec.DecryptAppleLegacyAppPayload(ProductControlTrafficPadding.Unwrap(
                (await Remote.ReadAsync(Deadline.Token)).ToArray()), AppKeys ?? throw new InvalidOperationException()));
        internal Task Send<T>(LanControlMessageKind kind, T body) => SendRaw(LanProductControlMessages.Encode(kind, body));
        internal Task SendRaw(byte[] bytes) => Remote.SendAsync(ProductControlTrafficPadding.Wrap(
            WebRtcControlChannelCodec.EncryptAppleLegacyAppPayload(bytes, AppKeys ?? throw new InvalidOperationException())), Deadline.Token);
        internal async Task Closed()
        {
            var bytes = new byte[1];
            try { Require(await Client.GetStream().ReadAsync(bytes, Deadline.Token) == 0, "Rejected handshake emitted product bytes."); }
            catch (IOException) { /* TCP reset is also terminal, unlike a deadline or a response. */ }
        }
        public async ValueTask DisposeAsync()
        {
            Deadline.Cancel(); await Remote.DisposeAsync();
            if (Accept.IsCompletedSuccessfully) await (await Accept).DisposeAsync();
            else { try { await Accept; } catch (Exception) when (Accept.IsFaulted || Accept.IsCanceled) { } }
            AppKeys?.Dispose(); Keys?.Dispose(); Deadline.Dispose();
        }
    }

    private sealed class UnusedApproval : ILanPibApprovalPresenter
    {
        public Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token) =>
            throw new InvalidOperationException("MessageA must not enter PIB approval.");
    }

    private static async Task IncomingAdmission(bool bootstrap)
    {
        foreach (var padded in new[] { false, true })
        {
            await using var f = await Incoming.Open(bootstrap);
            if (bootstrap) Require(f.TrustReads == 0 && f.PublishedTrusted.Length == 0,
                "MAIN froze authority before its first frame and before pairing could finish.");
            await f.BeginHandshake(padded);
            Require(!f.Accept.IsCompleted, "Responder FIN1 alone admitted MAIN.");
            await f.Finish();
            var local = LanProductControlMessages.Payload<LanProductIdentity>(await f.Read());
            Require(local.DeviceId == LocalId && local.FileTransferPort is null && local.Capabilities is { Length: 0 },
                "Incoming audio-only MAIN advertised a nonexistent file listener or changed its account ID.");
            var ping = LanProductControlMessages.Payload<LanProductPing>(await f.Read());
            await f.Send(LanControlMessageKind.Identity, Identity(PeerId, PeerPublicKey));
            // Ordered ping/pong is a read barrier: the receiver processed identity,
            // but cannot return the session until its own admission ping is answered.
            var barrier = new LanProductPing(ping.Id ^ 1);
            await f.Send(LanControlMessageKind.Ping, barrier);
            Require(LanProductControlMessages.Payload<LanProductPing>(await f.Read()).Id == barrier.Id && !f.Accept.IsCompleted,
                "Identity alone admitted MAIN.");
            await f.Send(LanControlMessageKind.Pong, ping);
            var session = await f.Accept;
            if (bootstrap) Require(f.TrustReads == 1, "MAIN did not capture current approved authority at admission.");
            var binding = session.RequireAudioIdentityBinding();
            Require(binding.Role == ProductHandshakeRole.Responder && binding.LocalDeviceId == LocalId &&
                binding.PeerDeviceId == PeerId && f.Provider.WasDisposed && session.IsReady,
                "Incoming MAIN lost actual identity, role, or crypto ownership.");
            var pending = session.AcceptAudioOfferAsync(f.Deadline.Token);
            var streamId = Guid.NewGuid();
            await f.SendRaw(AudioStreamingLanEnvelope.Encode(new(streamId, new AudioStreamingBody.CaptureOffer(
                new(48000, 2, AudioStreamingEncoding.Float32, 32, 3)))));
            var inbox = await pending;
            Require((await inbox.ReadAsync(f.Deadline.Token)).StreamId == streamId, "MAIN sole reader did not hand off the encrypted audio offer.");
            inbox.Dispose();
            await using var route = await LanProductControlSessionTests.Fixture.Connect();
            await ThrowsAsync<InvalidDataException>(() => { session.RequireFileTransferRoute(route.Candidate); return Task.CompletedTask; });
            f.Deadline.Cancel();
            await session.Completion.WaitAsync(TimeSpan.FromSeconds(5));
            Require(!session.IsReady, "Canceled accepted MAIN retained readiness.");
        }
    }
    private static async Task UntrustedInitiator()
    {
        foreach (var a in new[] { MessageA(extensions: []), MessageA(Soa("different-local-device")),
            MessageA(key: Enumerable.Repeat((byte)99, 1952).ToArray()) })
        {
            await using var f = await Incoming.Open();
            await f.Remote.SendAsync(a.Encode(), f.Deadline.Token);
            await ThrowsAsync<InvalidDataException>(async () => { await f.Accept; });
            Require(f.CryptoCreations == 0, "Untrusted candidate reached private crypto.");
            await f.Closed();
        }
    }
    private static async Task NoApprovedPairing()
    {
        await using var f = await Incoming.Open(bootstrap: true);
        await f.Remote.SendAsync(MessageA().Encode(), f.Deadline.Token);
        await ThrowsAsync<InvalidOperationException>(async () => await f.Accept);
        await f.Closed();
        Require(f.TrustReads == 1 && f.PublishedTrusted.Length == 0 && f.CryptoCreations == 0,
            "Opening first-pair PIB admission also admitted an unpaired MAIN handshake.");
    }
    private static async Task InvalidFinished()
    {
        await using var f = await Incoming.Open(); await f.BeginHandshake(); await f.Finish(corrupt: true);
        await ThrowsAsync<ProductHandshakeException>(async () => { await f.Accept; });
        Require(f.Provider.WasDisposed, "Invalid FIN1 retained crypto owner."); await f.Closed();
    }
    private static async Task WrongProductIdentity()
    {
        await using var f = await Incoming.Open(); await f.BeginHandshake(); await f.Finish();
        await f.Read(); var ping = LanProductControlMessages.Payload<LanProductPing>(await f.Read());
        await f.Send(LanControlMessageKind.Identity, Identity("wrong-peer-device", PeerPublicKey));
        await ThrowsAsync<IOException>(async () => { await f.Accept; }); await f.Closed();
    }
    private static async Task OversizedPrefix()
    {
        await using var f = await Incoming.Open();
        var prefix = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(prefix, LanProductControlResponder.MaximumHandshakeFrameBytes + 1);
        await f.Client.GetStream().WriteAsync(prefix, f.Deadline.Token);
        await ThrowsAsync<InvalidDataException>(async () => { await f.Accept.WaitAsync(TimeSpan.FromSeconds(2)); });
        Require(f.CryptoCreations == 0, "Oversized pre-auth frame reached crypto."); await f.Closed();
    }
    private static async Task CanceledInitialRead()
    {
        await using var f = await Incoming.Open(); f.Deadline.Cancel();
        await ThrowsAsync<OperationCanceledException>(async () => { await f.Accept; });
        Require(f.CryptoCreations == 0, "Cancellation reached crypto.");
        using var verify = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        Require(await f.Client.GetStream().ReadAsync(new byte[1], verify.Token) == 0, "Canceled accept retained the socket.");
    }
    private static async Task CryptoCleanupFailure()
    {
        await using var f = await Incoming.Open(); f.Provider.ThrowOnDispose = true;
        await f.BeginHandshake(); await f.Finish();
        var error = await ThrowsAsync<LanResponderCryptoReleaseException>(async () => { await f.Accept; });
        Require(ReferenceEquals(error.RetainedOwner, f.Provider) && error.InnerException?.Message == "fixture crypto cleanup" &&
            f.Provider.WasDisposed, "Crypto release failure or its exact owner was hidden.");
        await f.Closed();
    }
    private static async Task HandshakeAndCleanupFailure()
    {
        await using var f = await Incoming.Open(); f.Provider.ThrowOnDispose = true;
        await f.BeginHandshake(); await f.Finish(corrupt: true);
        var error = await ThrowsAsync<LanResponderCryptoReleaseException>(async () => { await f.Accept; });
        Require(error.InnerException is AggregateException aggregate && aggregate.InnerExceptions.Count == 2 &&
            aggregate.InnerExceptions[0] is ProductHandshakeException && aggregate.InnerExceptions[1].Message == "fixture crypto cleanup" &&
            ReferenceEquals(error.RetainedOwner, f.Provider), "Cleanup masked handshake failure or discarded its unreleased owner.");
        await f.Closed();
    }
    private static async Task BootstrapRejected()
    {
        await using var f = await Incoming.Open();
        await f.Remote.SendAsync("{\"kemRefreshRequest\":{}}"u8.ToArray(), f.Deadline.Token);
        await ThrowsAsync<WebRtcProductHandshakeCodecException>(async () => { await f.Accept; });
        Require(f.CryptoCreations == 0, "Unimplemented bootstrap obtained private crypto authority.");
        await f.Closed();
    }
    private static async Task OversizedFinished()
    {
        await using var f = await Incoming.Open(); await f.BeginHandshake();
        var prefix = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(prefix, LanProductControlResponder.MaximumHandshakeFrameBytes + 1);
        await f.Client.GetStream().WriteAsync(prefix, f.Deadline.Token);
        await ThrowsAsync<InvalidDataException>(async () => { await f.Accept.WaitAsync(TimeSpan.FromSeconds(2)); });
        Require(f.Provider.WasDisposed, "Oversized Finished retained crypto."); await f.Closed();
    }
    private static async Task LocalCapabilities()
    {
        foreach (ushort? port in new ushort?[] { null, 8080 })
        {
            var local = LanProductControlMessages.LocalIdentity(Account, Pairing, port, DateTimeOffset.UtcNow);
            Require(local.Capabilities!.Contains("file_transfer") == (port is not null), "File capability does not match listener presence.");
        }
        await ThrowsAsync<InvalidDataException>(() => { LanProductControlMessages.LocalIdentity(Account, Pairing, 0, DateTimeOffset.UtcNow); return Task.CompletedTask; });
        await ThrowsAsync<InvalidDataException>(() => { LanProductControlMessages.LocalIdentity(Account with { DeviceId = LocalId[3..] }, Pairing, null, DateTimeOffset.UtcNow); return Task.CompletedTask; });
    }
    private static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

}
